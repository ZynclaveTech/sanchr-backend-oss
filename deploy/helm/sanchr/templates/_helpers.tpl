{{/*
Expand the name of the chart.
*/}}
{{- define "sanchr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "sanchr.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sanchr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sanchr.labels" -}}
helm.sh/chart: {{ include "sanchr.chart" . }}
{{ include "sanchr.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sanchr.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sanchr.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for the core component
*/}}
{{- define "sanchr.core.selectorLabels" -}}
{{ include "sanchr.selectorLabels" . }}
app.kubernetes.io/component: core
{{- end }}

{{/*
Selector labels for the call component
*/}}
{{- define "sanchr.call.selectorLabels" -}}
{{ include "sanchr.selectorLabels" . }}
app.kubernetes.io/component: call
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sanchr.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sanchr.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
