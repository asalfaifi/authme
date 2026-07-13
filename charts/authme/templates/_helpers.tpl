{{/* Expand the chart name. */}}
{{- define "authme.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a stable, DNS-safe release name. */}}
{{- define "authme.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "authme.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "authme.baseSelectorLabels" -}}
app.kubernetes.io/name: {{ include "authme.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "authme.selectorLabels" -}}
{{ include "authme.baseSelectorLabels" . }}
app.kubernetes.io/component: server
{{- end }}

{{- define "authme.labels" -}}
helm.sh/chart: {{ include "authme.chart" . }}
{{ include "authme.baseSelectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: authme
{{- end }}

{{- define "authme.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "authme.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "authme.configMapName" -}}
{{- default (include "authme.fullname" .) .Values.config.existingConfigMap }}
{{- end }}

{{- define "authme.migrationName" -}}
{{- printf "%s-migrate" (include "authme.fullname" . | trunc 55 | trimSuffix "-") }}
{{- end }}

{{- define "authme.testName" -}}
{{- printf "%s-test-connection" (include "authme.fullname" . | trunc 47 | trimSuffix "-") }}
{{- end }}

{{- define "authme.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
OpenShift restricted SCCs allocate an arbitrary UID/GID. Live installs detect
the SCC API; openshift.enabled supports deterministic offline rendering.
*/}}
{{- define "authme.isOpenShift" -}}
{{- if or .Values.openshift.enabled (.Capabilities.APIVersions.Has "security.openshift.io/v1") (.Capabilities.APIVersions.Has "security.openshift.io/v1/SecurityContextConstraints") (.Capabilities.APIVersions.Has "route.openshift.io/v1") -}}true{{- else -}}false{{- end -}}
{{- end }}

{{- define "authme.runtimeSecretChecksum" -}}
{{- printf "%s:%s" .Values.runtimeSecret.existingSecret .Values.runtimeSecret.checksum | sha256sum }}
{{- end }}

{{- define "authme.jwksSecretChecksum" -}}
{{- printf "%s:%s" .Values.jwks.existingSecret .Values.jwks.checksum | sha256sum }}
{{- end }}
