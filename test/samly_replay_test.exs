defmodule Samly.ReplayTest do
  # Samly.ReplayCache keeps its provider in the application env.
  use ExUnit.Case, async: false
  use Plug.Test

  require Samly.Esaml
  alias Samly.{Esaml, Helper, IdpData, ReplayCache, SPHandler}

  @consume_uri "https://sp.example.com/sso/sp/consume/idp1"
  @sp_entity_id "https://sp.example.com"
  @idp_entity_id "https://idp.example.com"

  setup do
    table = :"samly_replay_test_#{System.unique_integer([:positive])}"
    ReplayCache.init(Samly.ReplayCache.ETS, table: table)
    [table: table]
  end

  describe "Samly.ReplayCache.ETS" do
    test "accepts an assertion once", %{table: table} do
      expires_at = DateTime.add(DateTime.utc_now(), 300, :second)

      assert :ok = Samly.ReplayCache.ETS.check_and_put("id1", expires_at, table)
      assert {:error, :replayed} = Samly.ReplayCache.ETS.check_and_put("id1", expires_at, table)
      assert :ok = Samly.ReplayCache.ETS.check_and_put("id2", expires_at, table)
    end

    test "forgets an assertion once it has expired", %{table: table} do
      expired = DateTime.add(DateTime.utc_now(), -1, :second)
      expires_at = DateTime.add(DateTime.utc_now(), 300, :second)

      assert :ok = Samly.ReplayCache.ETS.check_and_put("id1", expired, table)
      assert :ok = Samly.ReplayCache.ETS.check_and_put("id1", expires_at, table)
    end
  end

  describe "Samly.ReplayCache.DETS" do
    setup do
      table = :"samly_replay_dets_#{System.unique_integer([:positive])}"
      path = Path.join(System.tmp_dir!(), "#{table}.dets")

      on_exit(fn ->
        _ = :dets.close(table)
        File.rm(path)
      end)

      [table: table, path: path]
    end

    test "accepts an assertion once", %{table: table, path: path} do
      assert ^table = Samly.ReplayCache.DETS.init(table: table, file: path)
      expires_at = DateTime.add(DateTime.utc_now(), 300, :second)

      assert :ok = Samly.ReplayCache.DETS.check_and_put("id1", expires_at, table)
      assert {:error, :replayed} = Samly.ReplayCache.DETS.check_and_put("id1", expires_at, table)
      assert :ok = Samly.ReplayCache.DETS.check_and_put("id2", expires_at, table)
    end

    test "forgets an assertion once it has expired", %{table: table, path: path} do
      assert ^table = Samly.ReplayCache.DETS.init(table: table, file: path)
      expired = DateTime.add(DateTime.utc_now(), -1, :second)
      expires_at = DateTime.add(DateTime.utc_now(), 300, :second)

      assert :ok = Samly.ReplayCache.DETS.check_and_put("id1", expired, table)
      assert :ok = Samly.ReplayCache.DETS.check_and_put("id1", expires_at, table)
    end

    test "remembers accepted assertions across a reopen (restart)", %{table: table, path: path} do
      assert ^table = Samly.ReplayCache.DETS.init(table: table, file: path)
      expires_at = DateTime.add(DateTime.utc_now(), 300, :second)
      assert :ok = Samly.ReplayCache.DETS.check_and_put("id1", expires_at, table)

      # Close the table as a clean shutdown would, then reopen as a fresh boot.
      :ok = :dets.close(table)
      assert ^table = Samly.ReplayCache.DETS.init(table: table, file: path)

      assert {:error, :replayed} = Samly.ReplayCache.DETS.check_and_put("id1", expires_at, table)
    end
  end

  describe "Samly.ReplayCache.Mnesia (ram_copies, single node)" do
    setup do
      table = :"samly_replay_mnesia_#{System.unique_integer([:positive])}"
      opts = Samly.ReplayCache.Mnesia.init(table: table)
      on_exit(fn -> :mnesia.delete_table(table) end)

      [opts: opts]
    end

    test "accepts an assertion once", %{opts: opts} do
      expires_at = DateTime.add(DateTime.utc_now(), 300, :second)

      assert :ok = Samly.ReplayCache.Mnesia.check_and_put("id1", expires_at, opts)
      assert {:error, :replayed} = Samly.ReplayCache.Mnesia.check_and_put("id1", expires_at, opts)
      assert :ok = Samly.ReplayCache.Mnesia.check_and_put("id2", expires_at, opts)
    end

    test "forgets an assertion once it has expired", %{opts: opts} do
      expired = DateTime.add(DateTime.utc_now(), -1, :second)
      expires_at = DateTime.add(DateTime.utc_now(), 300, :second)

      assert :ok = Samly.ReplayCache.Mnesia.check_and_put("id1", expired, opts)
      assert :ok = Samly.ReplayCache.Mnesia.check_and_put("id1", expires_at, opts)
    end
  end

  describe "Samly.ReplayCache" do
    test "identifies an assertion by its signed content" do
      assertion = assertion_rec(issue_instant: "2026-10-16T10:00:00Z")
      same = assertion_rec(issue_instant: "2026-10-16T10:00:00Z")
      other = assertion_rec(issue_instant: "2026-10-16T10:00:01Z")

      assert :ok = ReplayCache.check_and_put(assertion)
      assert {:error, :replayed} = ReplayCache.check_and_put(same)
      assert :ok = ReplayCache.check_and_put(other)
    end

    test "keeps an assertion until its NotOnOrAfter" do
      not_on_or_after = "2026-10-16T10:05:00Z"
      assertion = assertion_rec(not_on_or_after: not_on_or_after) |> Samly.Assertion.from_rec()

      assert ReplayCache.expires_at(assertion) == ~U[2026-10-16 10:05:00Z]
    end
  end

  describe "decode_idp_auth_resp/3" do
    test "rejects a replayed SAML response (CVE-2026-53424)" do
      saml_response = saml_response(in_response_to: "_req1") |> Base.encode64()

      assert {:ok, assertion} = Helper.decode_idp_auth_resp(sp(), nil, saml_response)
      assert assertion.subject.name == "user@example.com"
      assert assertion.subject.in_response_to == "_req1"

      assert {:error, :duplicate} = Helper.decode_idp_auth_resp(sp(), nil, saml_response)
    end
  end

  describe "authn_request_id/1" do
    test "returns the ID of the generated AuthnRequest" do
      xml_frag =
        :esaml_sp.generate_authn_request(~c"https://idp.example.com/sso", sp(), :undefined)

      request_id = Helper.authn_request_id(xml_frag)
      assert is_binary(request_id) and request_id != ""

      xml = :xmerl.export([xml_frag], :xmerl_xml) |> to_string()
      assert xml =~ ~s(ID="#{request_id}")
    end
  end

  describe "validate_authresp/3 in the SP-initiated flow (CVE-2026-53425)" do
    test "accepts a response to the AuthnRequest of this session" do
      conn = sp_initiated_conn(%{"authn_request_id" => "_req1"})
      assert :ok = SPHandler.validate_authresp(conn, assertion("_req1"), "rs1")
    end

    test "rejects a response to another AuthnRequest" do
      conn = sp_initiated_conn(%{"authn_request_id" => "_req1"})

      assert {:error, :invalid_in_response_to} =
               SPHandler.validate_authresp(conn, assertion("_other"), "rs1")
    end

    test "rejects a response when this session sent no AuthnRequest" do
      conn = sp_initiated_conn(%{})

      assert {:error, :invalid_in_response_to} =
               SPHandler.validate_authresp(conn, assertion("_req1"), "rs1")
    end
  end

  defp sp do
    Esaml.esaml_sp(
      consume_uri: String.to_charlist(@consume_uri),
      metadata_uri: ~c"https://sp.example.com/sso/sp/metadata/idp1",
      entity_id: String.to_charlist(@sp_entity_id),
      idp_signs_assertions: false,
      idp_signs_envelopes: false,
      trusted_fingerprints: []
    )
  end

  defp sp_initiated_conn(session) do
    session =
      Map.merge(%{"relay_state" => "rs1", "idp_id" => "idp1", "target_url" => "/"}, session)

    conn(:post, "/sso/sp/consume/idp1")
    |> init_test_session(session)
    |> put_private(:samly_idp, %IdpData{id: "idp1"})
  end

  defp assertion(in_response_to) do
    %Samly.Assertion{subject: %Samly.Subject{name: "user", in_response_to: in_response_to}}
  end

  defp assertion_rec(opts) do
    Esaml.esaml_assertion(
      issue_instant: Keyword.get(opts, :issue_instant, "2026-10-16T10:00:00Z") |> to_charlist(),
      issuer: String.to_charlist(@idp_entity_id),
      subject:
        Esaml.esaml_subject(
          name: ~c"user@example.com",
          notonorafter:
            Keyword.get(opts, :not_on_or_after, "2099-01-01T00:00:00Z") |> to_charlist(),
          in_response_to: ~c"_req1"
        ),
      authn: [session_index: ~c"_session1"]
    )
  end

  defp saml_response(opts) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    issue_instant = DateTime.to_iso8601(now)
    not_before = now |> DateTime.add(-60, :second) |> DateTime.to_iso8601()
    not_on_or_after = now |> DateTime.add(300, :second) |> DateTime.to_iso8601()

    """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response1" Version="2.0" IssueInstant="#{issue_instant}" Destination="#{@consume_uri}">
      <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_assertion1" Version="2.0" IssueInstant="#{issue_instant}">
        <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
        <saml:Subject>
          <saml:NameID>user@example.com</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="#{opts[:in_response_to]}" NotOnOrAfter="#{not_on_or_after}" Recipient="#{@consume_uri}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="#{not_before}" NotOnOrAfter="#{not_on_or_after}">
          <saml:AudienceRestriction><saml:Audience>#{@sp_entity_id}</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="#{issue_instant}" SessionIndex="_session1">
          <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
        </saml:AuthnStatement>
      </saml:Assertion>
    </samlp:Response>
    """
  end
end
