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

{{- define "aegis.image" -}}
{{- $reg := .root.Values.global.imageRegistry -}}
{{- $tag := .image.tag | default .root.Chart.AppVersion -}}
{{- $ref := printf "%s:%s" .image.repository $tag -}}
{{- if $reg }}{{ $ref = printf "%s/%s" $reg $ref }}{{ end -}}
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
    {{- with $np.dataPlaneEgressDenyIPv6 }}
    except: {{- toYaml . | nindent 6 }}
    {{- end }}
{{- end }}
{{- end -}}
