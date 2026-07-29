export const queryKeys = {
  appInfo: ["app-info"] as const,
  runtime: ["runtime"] as const,
  bootstrap: ["runtime", "bootstrap"] as const,
  status: ["runtime", "status"] as const,
  devices: ["runtime", "devices"] as const,
  conflicts: ["runtime", "conflicts"] as const,
  history: ["runtime", "history"] as const,
  activity: ["runtime", "activity"] as const,
  monitoringSettings: ["runtime", "monitoring-settings"] as const,
  controlAudit: ["runtime", "control-audit"] as const,
}
