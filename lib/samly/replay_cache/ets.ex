defmodule Samly.ReplayCache.ETS do
  @moduledoc """
  Keeps accepted SAML assertion identifiers in ETS until they expire.

  This is the default replay cache. It is local to one node: use a shared
  store in a multi-node deployment (see `Samly.ReplayCache.Store`).

  ## Options

  +   `:table` - ETS table name (optional)
                 Value must be an atom

  ## Configuration Example

      config :samly, Samly.ReplayCache,
        opts: [table: :my_replay_cache_table]
  """

  @behaviour Samly.ReplayCache.Store

  @replay_table :samly_replay_cache_table

  @impl Samly.ReplayCache.Store
  def init(opts) do
    replay_table = Keyword.get(opts, :table, @replay_table)

    if is_atom(replay_table) == false do
      raise "Samly.ReplayCache.ETS table name must be an atom: #{inspect(replay_table)}"
    end

    if :ets.info(replay_table) == :undefined do
      :ets.new(replay_table, [:set, :public, :named_table, write_concurrency: true])
    end

    replay_table
  end

  @impl Samly.ReplayCache.Store
  def check_and_put(assertion_id, %DateTime{} = expires_at, replay_table) do
    purge_expired(replay_table, System.system_time(:second))

    if :ets.insert_new(replay_table, {assertion_id, DateTime.to_unix(expires_at)}) do
      :ok
    else
      {:error, :replayed}
    end
  end

  defp purge_expired(replay_table, now) do
    :ets.select_delete(replay_table, [{{:_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
  end
end
