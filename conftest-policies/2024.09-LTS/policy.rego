package main


deny contains msg if {
  key := object.keys(input.applications)[_]
  app := input.applications[key]
  app.values.resources.requests.memory != app.values.resources.limits.memory
  msg := sprintf("Memory request (%v) and limit (%v) must be equal for application %v", [app.values.resources.requests.memory, app.values.resources.limits.memory, key])
}


warn contains msg if {
  key := object.keys(input.applications)[_]
  app := input.applications[key]
  reqMem := app.values.resources.requests.memory
  not endswith(reqMem, "Mi")
  not endswith(reqMem, "Gi")
  limMem := app.values.resources.limits.memory
  not endswith(limMem, "Mi")
  not endswith(limMem, "Gi")

  msg := sprintf("Memory resources must be specified in Mi or Gi for application %v", [key])
}

warn contains msg if {
  key := object.keys(input.applications)[_]
  app := input.applications[key]
  reqMem := app.values.resources.requests.memory
  contains(reqMem, ".")
  msg := sprintf("Memory request (%v) for application %v must not be in decimal units (must not contain a dot)", [reqMem, key])
}

warn contains msg if {
  key := object.keys(input.applications)[_]
  app := input.applications[key]
  limMem := app.values.resources.limits.memory
  contains(limMem, ".")
  msg := sprintf("Memory limit (%v) for application %v must not be in decimal units (must not contain a dot)", [limMem, key])
}

warn_single_replicas contains msg if {
  key := object.keys(input.applications)[_]
  app := input.applications[key]
  app.values.replicaCount <= 1
  msg := sprintf("ReplicaCount should be higher than 1 - currently %v for  %v", [app.values.replicaCount, key])
}

warn_cpu_limit_too_higher contains msg if {
  key := object.keys(input.applications)[_]
  app := input.applications[key]
  reqCpu := parse_cpu(app.values.resources.requests.cpu)
  limCpu := parse_cpu(app.values.resources.limits.cpu)
  limCpu > reqCpu * 2
  msg := sprintf("CPU limit (%v) for application %v is more than twice the request (%v)", [app.values.resources.limits.cpu, key, app.values.resources.requests.cpu])
}

# Helper function to parse CPU values ("100m" -> 0.1, "1" -> 1.0)
parse_cpu(cpu) = val if {
  endswith(cpu, "m")
  val := to_number(trim_suffix(cpu, "m")) / 1000
}

parse_cpu(cpu) = val if {
  not endswith(cpu, "m")
  val := to_number(cpu)
}
