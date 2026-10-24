{{- define "aegis.name" -}}{{ .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}

{{- define "aegis.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "aegis.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aegisproxy
{{- end -}}

{{- define "aegis.selector" -}}
app.kubernetes.io/name: {{ include "aegis.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Image reference: repository[:tag][@digest]. The tag defaults to the release tag v<appVersion>;
global.imageRegistry replaces the registry host of the repository (a first path element with "." or ":",
or "localhost") or is prepended when the repository has none (Docker Hub). */}}
{{- define "aegis.image" -}}
{{- $repo := .image.repository -}}
{{- with .root.Values.global.imageRegistry -}}
{{- $parts := splitList "/" $repo -}}
{{- $first := first $parts -}}
{{- if and (gt (len $parts) 1) (or (contains "." $first) (contains ":" $first) (eq $first "localhost")) -}}
{{- $repo = join "/" (rest $parts) -}}
{{- end -}}
{{- $repo = printf "%s/%s" (trimSuffix "/" .) $repo -}}
{{- end -}}
{{- $tag := .image.tag | default (printf "v%s" .root.Chart.AppVersion) -}}
{{- $ref := printf "%s:%s" $repo $tag -}}
{{- if .image.digest }}{{ $ref = printf "%s@%s" $ref .image.digest }}{{ end -}}
{{- $ref -}}
{{- end -}}

{{- define "aegis.secretName" -}}{{ .Values.secrets.existingSecret | default (printf "%s-secrets" (include "aegis.fullname" .)) }}{{- end -}}
{{- define "aegis.caSecretName" -}}{{ .Values.ca.existingSecret | default (printf "%s-ca" (include "aegis.fullname" .)) }}{{- end -}}
{{- define "aegis.cpService" -}}{{ printf "%s-control-plane" (include "aegis.fullname" .) }}{{- end -}}
{{- define "aegis.cnpgName" -}}{{ printf "%s-pg" (include "aegis.fullname" .) }}{{- end -}}

{{- define "aegis.dbSecretName" -}}
{{- if .Values.storage.postgres.cnpg.enabled -}}{{ printf "%s-app" (include "aegis.cnpgName" .) }}
{{- else if .Values.storage.postgres.existingSecret -}}{{ .Values.storage.postgres.existingSecret }}
{{- else -}}{{ include "aegis.secretName" . }}{{- end -}}
{{- end -}}

{{- define "aegis.dbSecretKey" -}}
{{- if .Values.storage.postgres.cnpg.enabled -}}uri
{{- else if .Values.storage.postgres.existingSecret -}}{{ .Values.storage.postgres.existingSecretKey }}
{{- else -}}database-url{{- end -}}
{{- end -}}

{{- define "aegis.cpReplicas" -}}
{{- if eq .Values.storage.type "file" -}}1{{- else -}}{{ .Values.controlPlane.replicas }}{{- end -}}
{{- end -}}

{{- define "aegis.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "aegis.validate" -}}
{{- if not (has .Values.storage.type (list "postgres" "file")) -}}{{ fail "storage.type must be postgres or file" }}{{- end -}}
{{- if and (eq .Values.storage.type "postgres") (not .Values.storage.postgres.cnpg.enabled) (not .Values.storage.postgres.existingSecret) (not .Values.storage.postgres.url) -}}
{{ fail "storage.type=postgres requires storage.postgres.url, storage.postgres.existingSecret or storage.postgres.cnpg.enabled=true" }}
{{- end -}}
{{- if and (not .Values.ca.existingSecret) (not .Values.ca.generate) -}}{{ fail "set ca.existingSecret or ca.generate=true" }}{{- end -}}
{{- if not (hasPrefix "http" .Values.publicUrl) -}}{{ fail "publicUrl must be an absolute http(s) URL" }}{{- end -}}
{{- if not (has .Values.probes.mode (list "http" "exec")) -}}{{ fail "probes.mode must be http or exec" }}{{- end -}}
{{- $svc := .Values.dataPlane.service -}}
{{- if and (eq $svc.type "LoadBalancer") (not $svc.loadBalancerSourceRanges) (not (and .Values.networkPolicy.enabled .Values.networkPolicy.proxyClientCIDRs)) (not $svc.allowPublicProxy) -}}
{{ fail "dataPlane.service.type=LoadBalancer exposes the proxy to every network that reaches the load balancer: restrict it to the server networks with dataPlane.service.loadBalancerSourceRanges or networkPolicy.proxyClientCIDRs, use an internal load balancer (dataPlane.service.annotations) together with one of them, or set dataPlane.service.allowPublicProxy=true deliberately" }}
{{- end -}}
{{- if and .Values.networkPolicy.dataPlaneEgressIPv6 (not .Values.networkPolicy.clusterIPv6CIDRs) -}}
{{ fail "networkPolicy.dataPlaneEgressIPv6=true requires networkPolicy.clusterIPv6CIDRs: list the cluster's pod, service, node and VPC IPv6 ranges (or [\"fc00::/7\"] when they are unique-local) so they are not reachable as internet" }}
{{- end -}}
{{- $tc := .Values.ingress.trustedController -}}
{{- if and $tc.enabled (not $tc.existingServiceFQDN) (or (not $tc.namespace) (not $tc.podLabels)) -}}
{{ fail "ingress.trustedController needs namespace and podLabels of the ingress controller pods (or existingServiceFQDN)" }}
{{- end -}}
{{- end -}}

{{/* Absolute DNS name (trailing dot) of the headless Service of the trusted ingress controller pods. */}}
{{- define "aegis.trustedControllerHost" -}}
{{- $tc := .Values.ingress.trustedController -}}
{{- if $tc.existingServiceFQDN -}}{{ printf "%s." (trimSuffix "." $tc.existingServiceFQDN) }}
{{- else -}}{{ printf "%s-ingress-peers.%s.svc.%s." (include "aegis.fullname" .) $tc.namespace (trimSuffix "." .Values.clusterDomain) }}
{{- end -}}
{{- end -}}

{{/* DNS egress: the cluster DNS pods in their namespace (plus extraDnsEgress peers). */}}
{{- define "aegis.dnsEgress" -}}
{{- $np := .Values.networkPolicy -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ $np.dns.namespace }}
      podSelector:
        matchLabels: {{- toYaml $np.dns.podLabels | nindent 10 }}
    {{- with $np.extraDnsEgress }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  ports:
    - { port: 53, protocol: UDP }
    - { port: 53, protocol: TCP }
{{- end -}}

{{/* Internet egress peers: IPv4 and (optionally) IPv6 without the internal ranges of networkPolicy. */}}
{{- define "aegis.publicEgress" -}}
{{- $np := .Values.networkPolicy -}}
- ipBlock:
    cidr: 0.0.0.0/0
    {{- with $np.dataPlaneEgressDeny }}
    except: {{- toYaml . | nindent 6 }}
    {{- end }}
{{- if $np.dataPlaneEgressIPv6 }}
- ipBlock:
    cidr: "::/0"
    {{- with concat ($np.dataPlaneEgressDenyIPv6 | default list) ($np.clusterIPv6CIDRs | default list) | uniq }}
    except: {{- toYaml . | nindent 6 }}
    {{- end }}
{{- end }}
{{- end -}}
