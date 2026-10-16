defmodule Samly.ReplayCache.Store do
  @moduledoc """
  Specification for Samly assertion replay caches.

  SAML 2.0 Profiles §4.1.4.5 requires a service provider to accept a bearer
  assertion only once. Samly records every accepted assertion in a replay
  cache until the assertion expires, and rejects an assertion that is already
  present.

  The cache must be shared by every node that consumes SAML responses. The
  default `Samly.ReplayCache.ETS` store is local to one node: a multi-node
  deployment must provide a shared store (database, Redis, ...) or an
  assertion captured on one node can be replayed on another.
  """

  @typedoc """
  Options passed during the cache initialization.
  """
  @type opts :: Plug.opts()

  @typedoc """
  Stable identifier of an assertion, derived from its signed content.
  """
  @type assertion_id :: binary

  @doc """
  Initializes the cache.

  The options returned from this function will be given to `check_and_put/3`.
  """
  @callback init(opts()) :: opts() | no_return()

  @doc """
  Records `assertion_id` until `expires_at` if it is not already present.

  Returns `:ok` when the assertion is seen for the first time and
  `{:error, :replayed}` when it is already in the cache. The check and the
  insertion must be atomic, otherwise two concurrent requests replaying the
  same assertion can both be accepted.
  """
  @callback check_and_put(assertion_id(), expires_at :: DateTime.t(), opts()) ::
              :ok | {:error, :replayed}
end
