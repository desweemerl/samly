defmodule Samly.ReplayCache.DETS do
  @moduledoc """
  Keeps accepted SAML assertion identifiers in a DETS (disk) table until they
  expire.

  Unlike `Samly.ReplayCache.ETS`, the table is backed by a file, so accepted
  assertions survive a node restart.

  It is still **local to one node**: the file lives on that node's filesystem.
  A multi-node deployment that needs a single shared cache must provide a
  shared store (database, Redis, ...) - see `Samly.ReplayCache.Store`. When
  this store is used across several nodes, each node must point at its own
  file, and on ephemeral hosts (containers) that file must sit on a persistent
  volume, otherwise a restart loses the cache.

  Durability: entries are flushed to disk on the `:auto_save` interval and on a
  clean shutdown. A hard crash can lose entries written since the last save and
  leaves the file marked as not properly closed, which DETS repairs on the next
  open. That is acceptable for a replay cache - the entries are short-lived and
  the assertion signature remains the primary protection.

  ## Options

  +   `:table`     - DETS table name (optional, must be an atom)
  +   `:file`      - path to the DETS file (optional; defaults to
                     `"<table>.dets"` in the current directory - set an
                     absolute path on a persistent volume in production)
  +   `:auto_save` - auto-save interval in milliseconds, or `:infinity` to only
                     persist on a clean close (optional, default `60_000`)

  ## Configuration Example

      config :samly, Samly.ReplayCache,
        cache: Samly.ReplayCache.DETS,
        opts: [file: "/var/lib/genexir/samly_replay_cache.dets"]
  """

  @behaviour Samly.ReplayCache.Store

  @replay_table :samly_replay_cache_table
  @default_auto_save 60_000

  @impl Samly.ReplayCache.Store
  def init(opts) do
    table = Keyword.get(opts, :table, @replay_table)

    if is_atom(table) == false do
      raise "Samly.ReplayCache.DETS table name must be an atom: #{inspect(table)}"
    end

    file = opts |> Keyword.get(:file, "#{table}.dets") |> to_string()
    auto_save = Keyword.get(opts, :auto_save, @default_auto_save)

    File.mkdir_p!(Path.dirname(Path.expand(file)))

    if :dets.info(table) == :undefined do
      case :dets.open_file(table,
             file: String.to_charlist(file),
             type: :set,
             auto_save: auto_save
           ) do
        {:ok, ^table} ->
          :ok

        {:error, reason} ->
          raise "Samly.ReplayCache.DETS could not open #{inspect(file)}: #{inspect(reason)}"
      end
    end

    table
  end

  @impl Samly.ReplayCache.Store
  def check_and_put(assertion_id, %DateTime{} = expires_at, table) do
    purge_expired(table, System.system_time(:second))

    if :dets.insert_new(table, {assertion_id, DateTime.to_unix(expires_at)}) do
      :ok
    else
      {:error, :replayed}
    end
  end

  defp purge_expired(table, now) do
    :dets.select_delete(table, [{{:_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
  end
end
