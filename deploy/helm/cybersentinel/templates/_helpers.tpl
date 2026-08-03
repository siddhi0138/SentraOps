{{- define "cybersentinel.name" -}}
cybersentinel
{{- end -}}

{{- define "cybersentinel.fullname" -}}
{{ .Release.Name }}-cybersentinel
{{- end -}}

{{- define "cybersentinel.labels" -}}
app.kubernetes.io/name: {{ include "cybersentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
