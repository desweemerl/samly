defmodule Samly.ReplayCache.Mnesia do
  @moduledoc """
  Keeps accepted SAML assertion identifiers in a replicated Mnesia table until
  they expire.

  Unlike `Samly.ReplayCache.ETS` and `Samly.ReplayCache.DETS`, this store is
  **shared across the cluster**: the table is replicated on every connected
  node, so an assertion accepted on one node is refused on any other. This is
  the store to use in a multi-node deployment behind a load balancer, where the
  response to an IdP-initiated login can land on a different node than expected.

  It relies on the nodes being connected over Erlang distribution (see
  `Node.list/0`); no external dependency is required (Mnesia ships with OTP).

  ## Storage type

  The `:storage` option selects how copies are held:

  +   `:ram_copies` (default) - in memory, replicated. No disk, so none of the
      Mnesia-in-containers pitfalls apply. Survives a **rolling** restart: a
      rebooted node rejoins and re-syncs the table from its peers. The cache is
      lost only if **every** node is down at once - acceptable here, because
      entries are short-lived (they expire with the assertion) and the
      signature remains the primary protection.
  +   `:disc_copies` - also persisted to disk, so it survives a full-cluster
      restart. **Experimental here:** Mnesia's on-disk schema is pinned to node
      names, and container node names (`name@<ip>`) change on every redeploy,
      which leads to schema mismatches. Use it only with stable node names and a
      persistent Mnesia directory per node (`:dir`).

  ## Options

  +   `:table`        - table name (optional, must be an atom)
  +   `:storage`      - `:ram_copies` (default) or `:disc_copies`
  +   `:wait_timeout` - ms to wait for the table to be available (default 10_000)
  +   `:dir`          - Mnesia directory, `:disc_copies` only

  ## Configuration Example

      config :samly, Samly.ReplayCache,
        cache: Samly.ReplayCache.Mnesia,
        opts: [storage: :ram_copies]

  ## Availability

  If the replay check itself cannot run (table unavailable, transaction
  aborted), this store **fails open**: it logs an error and lets the login
  proceed, rather than locking every user out over a cache fault. The signature,
  audience, recipient and validity checks - and, for the SP-initiated flow, the
  `InResponseTo` binding - still apply, so a cache outage degrades replay
  protection to defense-in-depth rather than removing authentication security.
  """

  @behaviour Samly.ReplayCache.Store

  require Logger

  @replay_table :samly_replay_cache
  @wait_timeout 10_000

  @impl Samly.ReplayCache.Store
  def init(opts) do
    table = Keyword.get(opts, :table, @replay_table)

    if is_atom(table) == false do
      raise "Samly.ReplayCache.Mnesia table name must be an atom: #{inspect(table)}"
    end

    storage = Keyword.get(opts, :storage, :ram_copies)

    if storage not in [:ram_copies, :disc_copies] do
      raise "Samly.ReplayCache.Mnesia :storage must be :ram_copies or :disc_copies: #{inspect(storage)}"
    end

    wait_timeout = Keyword.get(opts, :wait_timeout, @wait_timeout)

    start_mnesia!(storage, opts)
    join_cluster()
    ensure_table!(table, storage)
    prune_dead_copies(table, storage)

    case :mnesia.wait_for_tables([table], wait_timeout) do
      :ok ->
        :ok

      other ->
        raise "Samly.ReplayCache.Mnesia table #{inspect(table)} unavailable: #{inspect(other)}"
    end

    %{table: table}
  end

  @impl Samly.ReplayCache.Store
  def check_and_put(assertion_id, %DateTime{} = expires_at, %{table: table}) do
    purge_expired(table, System.system_time(:second))
    expires_unix = DateTime.to_unix(expires_at)

    txn = fn ->
      now = System.system_time(:second)

      case :mnesia.wread({table, assertion_id}) do
        [{^table, ^assertion_id, stored}] when stored > now ->
          :replayed

        _ ->
          # absent, or present but already expired - record it afresh
          :mnesia.write({table, assertion_id, expires_unix})
          :ok
      end
    end

    case :mnesia.transaction(txn) do
      {:atomic, :ok} ->
        :ok

      {:atomic, :replayed} ->
        {:error, :replayed}

      {:aborted, reason} ->
        # Fail open: never lock users out over a cache fault (see moduledoc).
        Logger.error("[Samly] replay cache transaction aborted: #{inspect(reason)}")
        :ok
    end
  end

  defp start_mnesia!(:disc_copies, opts) do
    case Keyword.get(opts, :dir) do
      nil -> :ok
      dir -> Application.put_env(:mnesia, :dir, String.to_charlist(to_string(dir)))
    end

    # A disc schema must exist before mnesia starts; ignore "already there".
    _ = :mnesia.create_schema([node() | Node.list()])
    start_mnesia_app!()
  end

  defp start_mnesia!(:ram_copies, _opts), do: start_mnesia_app!()

  defp start_mnesia_app! do
    case :mnesia.start() do
      :ok ->
        :ok

      {:error, {:already_started, :mnesia}} ->
        :ok

      {:error, reason} ->
        raise "Samly.ReplayCache.Mnesia could not start mnesia: #{inspect(reason)}"
    end
  end

  defp join_cluster do
    case :mnesia.change_config(:extra_db_nodes, Node.list()) do
      {:ok, _nodes} ->
        :ok

      {:error, reason} ->
        Logger.warning("[Samly] mnesia extra_db_nodes failed: #{inspect(reason)}")
    end
  end

  defp ensure_table!(table, storage) do
    attrs = [attributes: [:assertion_id, :expires_at], type: :set]

    # Create the copy on this node only; every other node adds its own copy via
    # ensure_local_copy!/2 when it boots. Replicating onto `Node.list()` at
    # create time would also place a copy on nodes that are merely connected
    # right now - e.g. the previous containers still draining during a rolling
    # deploy - leaving a stale "ghost" replica behind when they stop.
    case :mnesia.create_table(table, [{storage, [node()]} | attrs]) do
      {:atomic, :ok} ->
        :ok

      {:aborted, {:already_exists, ^table}} ->
        ensure_local_copy!(table, storage)

      {:aborted, reason} ->
        raise "Samly.ReplayCache.Mnesia create_table failed: #{inspect(reason)}"
    end
  end

  defp ensure_local_copy!(table, storage) do
    case :mnesia.add_table_copy(table, node(), storage) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, ^table, _node}} -> :ok
      {:aborted, reason} -> Logger.warning("[Samly] add_table_copy failed: #{inspect(reason)}")
    end
  end

  # Best-effort removal of replicas left on nodes that are no longer in the
  # cluster (e.g. the previous container after a redeploy). Harmless if it fails.
  defp prune_dead_copies(table, :ram_copies) do
    live = [node() | Node.list()]

    copies =
      try do
        :mnesia.table_info(table, :ram_copies)
      rescue
        _ -> []
      end

    Enum.each(copies -- live, fn dead ->
      try do
        :mnesia.del_table_copy(table, dead)
      rescue
        _ -> :ok
      end
    end)
  end

  defp prune_dead_copies(_table, _storage), do: :ok

  defp purge_expired(table, now) do
    spec = [{{table, :"$1", :"$2"}, [{:"=<", :"$2", now}], [:"$1"]}]

    expired =
      try do
        :mnesia.dirty_select(table, spec)
      rescue
        _ -> []
      end

    Enum.each(expired, fn id ->
      try do
        :mnesia.dirty_delete({table, id})
      rescue
        _ -> :ok
      end
    end)
  end
end
