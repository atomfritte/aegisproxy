// AegisProxy -> Microsoft Sentinel / Azure Monitor Logs (Logs Ingestion API).
// Creates the custom table, a data collection endpoint and rule, and grants the identity that
// AegisProxy uses (app registration, managed identity or workload identity) permission to ingest.
//
//   az deployment group create -g <rg> -f aegisproxy-sentinel.bicep \
//     -p workspaceName=<law> principalId=<object id of the service principal / managed identity>
//
// Outputs: the values for the "Microsoft Sentinel" log export destination in the AegisProxy console.

@description('Name of the existing Log Analytics workspace (Sentinel-enabled or not).')
param workspaceName string

@description('Object (principal) ID of the identity AegisProxy authenticates as.')
param principalId string

@description('principalType of principalId.')
@allowed(['ServicePrincipal', 'User', 'Group'])
param principalType string = 'ServicePrincipal'

param location string = resourceGroup().location

@description('Interactive retention of the table in days (total retention is configured on the workspace).')
@minValue(4)
@maxValue(730)
param retentionInDays int = 90

param tableName string = 'AegisProxy_CL'
param dceName string = 'dce-aegisproxy'
param dcrName string = 'dcr-aegisproxy'

var streamName = 'Custom-${tableName}'
var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'Stream', type: 'string' }
  { name: 'Severity', type: 'string' }
  { name: 'Message', type: 'string' }
  { name: 'EventId', type: 'string' }
  { name: 'Node', type: 'string' }
  { name: 'Action', type: 'string' }
  { name: 'Outcome', type: 'string' }
  { name: 'ServerName', type: 'string' }
  { name: 'ServerIP', type: 'string' }
  { name: 'Destination', type: 'string' }
  { name: 'Url', type: 'string' }
  { name: 'Method', type: 'string' }
  { name: 'RuleName', type: 'string' }
  { name: 'Actor', type: 'string' }
  { name: 'ThreatIndicator', type: 'string' }
  { name: 'ThreatSource', type: 'string' }
  { name: 'StatusCode', type: 'int' }
  { name: 'Data', type: 'dynamic' }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    schema: {
      name: tableName
      columns: columns
    }
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': {
        columns: columns
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'law'
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['law']
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [table]
}

// Monitoring Metrics Publisher on the DCR is the only permission AegisProxy needs.
var monitoringMetricsPublisher = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')

resource ingestRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, principalId, monitoringMetricsPublisher)
  scope: dcr
  properties: {
    roleDefinitionId: monitoringMetricsPublisher
    principalId: principalId
    principalType: principalType
  }
}

@description('Endpoint of the "Microsoft Sentinel" destination in AegisProxy.')
output logsIngestionEndpoint string = dce.properties.logsIngestion.endpoint

@description('DCR immutable ID of the "Microsoft Sentinel" destination.')
output dcrImmutableId string = dcr.properties.immutableId

@description('Stream name of the "Microsoft Sentinel" destination.')
output streamName string = streamName
