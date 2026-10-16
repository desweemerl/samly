defmodule Samly.ReplayCache do
  @moduledoc false

  alias Samly.Assertion

  @replay_cache :replay_cache

  # Fallback lifetime when the assertion carries no NotOnOrAfter at all.
  @default_ttl_seconds 300

  def init(cache_provider), do: init(cache_provider, [])

  def init(cache_provider, opts) do
    opts = cache_provider.init(opts)
    Application.put_env(:samly, @replay_cache, %{provider: cache_provider, opts: opts})
  end

  @doc false
  # Duplicate-check function given to `:esaml_sp.validate_assertion/3`. esaml
  # calls it after the signature, audience, recipient and validity window
  # checks, and rejects the response with `{:error, :duplicate}` unless it
  # returns `:ok`.
  def check_and_put(assertion_rec) do
    %{provider: cache_provider, opts: opts} = Application.fetch_env!(:samly, @replay_cache)
    assertion = Assertion.from_rec(assertion_rec)
    cache_provider.check_and_put(assertion_id(assertion), expires_at(assertion), opts)
  end

  @doc false
  # esaml does not expose the assertion's ID attribute, so the identifier is
  # derived from fields of the assertion itself. These fields are covered by
  # the assertion signature, unlike the response envelope around it.
  def assertion_id(%Assertion{} = assertion) do
    {
      assertion.issuer,
      assertion.subject.name,
      assertion.issue_instant,
      assertion.subject.in_response_to,
      Map.get(assertion.authn, "session_index", "")
    }
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  @doc false
  def expires_at(%Assertion{} = assertion) do
    [assertion.subject.notonorafter, Map.get(assertion.conditions, "not_on_or_after", "")]
    |> Enum.find_value(fn value ->
      case DateTime.from_iso8601(value) do
        {:ok, datetime, _offset} -> datetime
        _ -> nil
      end
    end)
    |> Kernel.||(DateTime.add(DateTime.utc_now(), @default_ttl_seconds, :second))
  end
end
