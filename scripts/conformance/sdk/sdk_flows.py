"""Drives the official Azure SDKs against the capture server (run in a container with --network host).

Each flow is announced to the capture log with a marker request so the requests can be attributed.
"""
import json, os, sys, urllib.request, ssl

from azure.identity import ClientSecretCredential, WorkloadIdentityCredential, ManagedIdentityCredential
from azure.monitor.ingestion import LogsIngestionClient
import msal
import azure.identity, azure.monitor.ingestion, azure.core

AUTH = "https://localhost:18443"
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
DCR = "dcr-00000000000000000000000000000000"
STREAM = "Custom-AegisProxy_CL"
ctx = ssl.create_default_context(cafile=os.environ["REQUESTS_CA_BUNDLE"])


def marker(name):
    try:
        urllib.request.urlopen(f"{AUTH}/__marker/{name}", context=ctx)
    except Exception:
        pass


print("versions:", json.dumps({"azure-identity": azure.identity.__version__ if hasattr(azure.identity, "__version__") else azure.identity._version.VERSION,
                               "azure-monitor-ingestion": azure.monitor.ingestion._version.VERSION, "azure-core": azure.core.__version__,
                               "msal": msal.__version__}))

marker("client_secret_upload")
cred = ClientSecretCredential(TENANT, CLIENT, "s3cret-value", authority=AUTH, disable_instance_discovery=True)
client = LogsIngestionClient(endpoint=AUTH, credential=cred, logging_enable=False)
# ~2.5 MB of records to observe chunking.
logs = [{"TimeGenerated": "2026-10-23T18:00:00.000000Z", "Stream": "audit", "Severity": "info", "Message": "x" * 900, "EventId": f"aud-{i}"} for i in range(2600)]
client.upload(rule_id=DCR, stream_name=STREAM, logs=logs)
client.upload(rule_id=DCR, stream_name=STREAM, logs=logs[:3])

marker("workload_identity")
open("/tmp/federated-token", "w").write("eyJhbGciOiJSUzI1NiJ9.federated.sig")
wi = WorkloadIdentityCredential(tenant_id=TENANT, client_id=CLIENT, token_file_path="/tmp/federated-token", authority=AUTH, disable_instance_discovery=True)
wi.get_token("https://monitor.azure.com//.default")

marker("managed_identity_system")
ManagedIdentityCredential().get_token("https://monitor.azure.com//.default")
marker("managed_identity_user")
ManagedIdentityCredential(client_id="uami-1").get_token("https://monitor.azure.com//.default")

marker("sovereign_us_scope")
# LogsIngestionClient derives the audience from credential_scopes; the docs require https://monitor.azure.us for US Gov.
gov = LogsIngestionClient(endpoint=AUTH, credential=ClientSecretCredential(TENANT, CLIENT, "s3cret-value", authority=AUTH, disable_instance_discovery=True),
                          credential_scopes=["https://monitor.azure.us//.default"])
gov.upload(rule_id=DCR, stream_name=STREAM, logs=logs[:1])

marker("msal_defender")
app = msal.ConfidentialClientApplication(CLIENT, client_credential="s3cret-value", authority=f"{AUTH}/{TENANT}", instance_discovery=False)
r = app.acquire_token_for_client(scopes=["https://api.securitycenter.microsoft.com/.default"])
print("msal token ok:", "access_token" in r)
marker("done")
print("done")
