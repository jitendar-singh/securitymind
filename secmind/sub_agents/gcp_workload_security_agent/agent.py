# secmind/sub_agents/gcp_workload_security_agent/agent.py

import re
from . import clients
from . import models
# Import the MemoryManager
from secmind.memory_manager import MemoryManager

# Initialize the memory manager for this agent's tools
memory = MemoryManager()

class GcpWorkloadSecurityAgent:
    """
    A sub-agent for Google Cloud Platform (GCP) workload security.
    """

    def run(self, instruction: str) -> models.GcpWorkloadSecurityResponse:
        """
        Runs the GCP Workload Security Agent.

        Args:
            instruction: The instruction for the agent.

        Returns:
            A response from the agent.
        """
        if "list gce instances for project" in instruction:
            project_id = instruction.split("list gce instances for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            # Check cache first
            cached_instances = memory.get_gce_instances(project_id)
            if cached_instances:
                return models.GcpWorkloadSecurityResponse(**cached_instances)

            client = clients.GcpWorkloadClient(project_id)
            try:
                instances = client.list_gce_instances()
                instance_names = [instance.name for instance in instances]
                response = models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Found {len(instance_names)} GCE instances in project {project_id}.",
                    data=instance_names,
                )
                # Add to cache
                memory.add_gce_instances(project_id, response.dict())
                return response
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while listing GCE instances: {e}",
                )

        elif "list gke clusters for project" in instruction:
            project_id = instruction.split("list gke clusters for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            # Check cache first
            cached_clusters = memory.get_gke_clusters(project_id)
            if cached_clusters:
                return models.GcpWorkloadSecurityResponse(**cached_clusters)

            client = clients.GcpWorkloadClient(project_id)
            try:
                clusters_raw = client.list_gke_clusters()
                clusters = [
                    models.GkeCluster(
                        name=c.name,
                        location=c.location,
                        status=c.status.name,
                        current_master_version=c.current_master_version,
                        private_cluster=c.private_cluster_config.enable_private_nodes,
                        datapath_provider=c.network_config.datapath_provider.name,
                        network=c.network.split('/')[-1],
                    )
                    for c in clusters_raw
                ]
                response = models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Found {len(clusters)} GKE clusters in project {project_id}.",
                    gke_clusters=clusters,
                )
                # Add to cache
                memory.add_gke_clusters(project_id, response.dict())
                return response
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while listing GKE clusters: {e}",
                )

        elif "list cloud run services for project" in instruction:
            project_id = instruction.split("list cloud run services for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            # Check cache first
            cached_services = memory.get_cloud_run_services(project_id)
            if cached_services:
                return models.GcpWorkloadSecurityResponse(**cached_services)

            client = clients.GcpWorkloadClient(project_id)
            try:
                services_raw = client.list_cloud_run_services()
                services = [
                    models.CloudRunService(
                        name=s.name.split('/')[-1],
                        location=s.location,
                        uri=s.uri,
                        creator=s.creator,
                        last_modifier=s.last_modifier,
                        ingress=s.ingress.name,
                        launch_stage=s.launch_stage.name,
                    )
                    for s in services_raw
                ]
                response = models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Found {len(services)} Cloud Run services in project {project_id}.",
                    cloud_run_services=services,
                )
                # Add to cache
                memory.add_cloud_run_services(project_id, response.dict())
                return response
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while listing Cloud Run services: {e}",
                )

        elif "list cloud functions for project" in instruction:
            project_id = instruction.split("list cloud functions for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            # Check cache first
            cached_functions = memory.get_cloud_functions(project_id)
            if cached_functions:
                return models.GcpWorkloadSecurityResponse(**cached_functions)

            client = clients.GcpWorkloadClient(project_id)
            try:
                functions_raw = client.list_cloud_functions()
                functions = [
                    models.CloudFunction(
                        name=f.name.split('/')[-1],
                        location=f.location,
                        state=f.state.name,
                        runtime=f.service_config.runtime,
                        environment=f.environment.name,
                        https_trigger_url=f.service_config.uri,
                        service_account=f.service_config.service_account,
                    )
                    for f in functions_raw
                ]
                response = models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Found {len(functions)} Cloud Functions in project {project_id}.",
                    cloud_functions=functions,
                )
                # Add to cache
                memory.add_cloud_functions(project_id, response.dict())
                return response
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while listing Cloud Functions: {e}",
                )

        elif "show firewall rules for project" in instruction:
            project_id = instruction.split("show firewall rules for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            # Check cache first
            cached_rules = memory.get_firewall_rules(project_id)
            if cached_rules:
                return models.GcpWorkloadSecurityResponse(**cached_rules)

            client = clients.GcpWorkloadClient(project_id)
            try:
                rules_raw = client.list_firewall_rules()
                rules = [
                    models.FirewallRule(
                        name=r.name,
                        description=r.description,
                        network=r.network.split('/')[-1],
                        direction=r.direction,
                        priority=r.priority,
                        source_ranges=r.source_ranges,
                        destination_ranges=r.destination_ranges,
                        allowed=[
                            models.FirewallRuleAllowed(
                                ip_protocol=a.i_p_protocol,
                                ports=a.ports,
                            )
                            for a in r.allowed
                        ],
                        denied=[
                            models.FirewallRuleAllowed(
                                ip_protocol=d.i_p_protocol,
                                ports=d.ports,
                            )
                            for d in r.denied
                        ],
                        disabled=r.disabled,
                    )
                    for r in rules_raw
                ]
                response = models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Found {len(rules)} firewall rules in project {project_id}.",
                    firewall_rules=rules,
                )
                # Add to cache
                memory.add_firewall_rules(project_id, response.dict())
                return response
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while listing firewall rules: {e}",
                )

        elif "get iam policy for project" in instruction:
            project_id = instruction.split("get iam policy for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            # Check cache first
            cached_policy = memory.get_iam_policy(project_id)
            if cached_policy:
                return models.GcpWorkloadSecurityResponse(**cached_policy)

            client = clients.GcpWorkloadClient(project_id)
            try:
                policy_raw = client.get_iam_policy()
                bindings = [
                    models.IamPolicyBinding(
                        role=b.role,
                        members=list(b.members),
                    )
                    for b in policy_raw.bindings
                ]
                policy = models.IamPolicy(
                    version=policy_raw.version,
                    bindings=bindings,
                    etag=policy_raw.etag.decode('utf-8'),
                )
                response = models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Successfully retrieved IAM policy for project {project_id}.",
                    iam_policy=policy,
                )
                # Add to cache
                memory.add_iam_policy(project_id, response.dict())
                return response
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while getting IAM policy: {e}",
                )

        elif "get details for gce instance" in instruction:
            match = re.search(r"get details for gce instance (.*) in zone (.*) for project (.*)", instruction)
            if not match:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Instruction not understood. Please use 'get details for gce instance <instance_name> in zone <zone> for project <project_id>'.",
                )

            instance_name, zone, project_id = match.groups()

            # Check cache first
            cached_details = memory.get_gce_instance_details(project_id, instance_name, zone)
            if cached_details:
                return models.GcpWorkloadSecurityResponse(**cached_details)

            client = clients.GcpWorkloadClient(project_id)
            try:
                instance_details_raw = client.get_gce_instance_details(instance=instance_name, zone=zone)

                service_accounts = [
                    models.GceServiceAccount(
                        email=sa.email,
                        scopes=sa.scopes
                    ) for sa in instance_details_raw.service_accounts
                ]

                network_interfaces = [
                    models.GceNetworkInterface(
                        name=ni.name,
                        network=ni.network,
                        network_ip=ni.network_ip,
                        access_configs=[ac.__class__.to_dict(ac) for ac in ni.access_configs]
                    ) for ni in instance_details_raw.network_interfaces
                ]

                # Get firewall rules for the instance
                all_rules_raw = client.list_firewall_rules()
                instance_tags = instance_details_raw.tags.items
                instance_networks = [ni.network for ni in instance_details_raw.network_interfaces]
                applicable_rules = []
                for rule in all_rules_raw:
                    # Firewall rule applies if it is on the same network and either has no target tags (applies to all)
                    # or has a target tag that is also on the instance.
                    if rule.network in instance_networks and (not rule.target_tags or any(tag in instance_tags for tag in rule.target_tags)):
                        applicable_rules.append(models.FirewallRule(
                            name=rule.name,
                            description=rule.description,
                            network=rule.network.split('/')[-1],
                            direction=rule.direction,
                            priority=rule.priority,
                            source_ranges=rule.source_ranges,
                            destination_ranges=rule.destination_ranges,
                            allowed=[
                                models.FirewallRuleAllowed(
                                    ip_protocol=a.i_p_protocol,
                                    ports=a.ports,
                                )
                                for a in rule.allowed
                            ],
                            denied=[
                                models.FirewallRuleAllowed(
                                    ip_protocol=d.i_p_protocol,
                                    ports=d.ports,
                                )
                                for d in rule.denied
                            ],
                            disabled=rule.disabled,
                        ))

                instance_details = models.GceInstanceDetails(
                    name=instance_details_raw.name,
                    machine_type=instance_details_raw.machine_type.split('/')[-1],
                    status=instance_details_raw.status,
                    zone=instance_details_raw.zone.split('/')[-1],
                    service_accounts=service_accounts,
                    network_interfaces=network_interfaces,
                    labels=instance_details_raw.labels,
                    metadata={m.key: m.value for m in instance_details_raw.metadata.items} if instance_details_raw.metadata else None,
                    firewall_rules=applicable_rules,
                )

                response = models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Successfully retrieved details for GCE instance {instance_name}.",
                    resource_details=instance_details,
                )
                # Add to cache
                memory.add_gce_instance_details(project_id, instance_name, zone, response.dict())
                return response
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while getting GCE instance details: {e}",
                )

        elif "scan container image" in instruction:
            match = re.search(r"scan container image (.*) for project (.*)", instruction)
            if not match:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Instruction not understood. Please use 'scan container image <resource_url> for project <project_id>'.",
                )

            resource_url, project_id = match.groups()

            # --- MEMORY INTEGRATION: Check cache first ---
            cached_result = memory.get_container_scan_result(resource_url)
            if cached_result:
                cached_result["message"] = f"(from cache) {cached_result['message']}"
                # Re-serialize into Pydantic models for consistency
                cached_result['vulnerabilities'] = [models.Vulnerability(**v) for v in cached_result['vulnerabilities']]
                return models.GcpWorkloadSecurityResponse(**cached_result)

            client = clients.GcpWorkloadClient(project_id)
            try:
                # --- If not in cache, perform the live scan ---
                vulnerabilities = client.get_container_vulnerabilities(resource_url)
                vuln_data = [
                    models.Vulnerability(
                        # Ensure CVE field exists, provide default if not
                        cve=v.vulnerability.cve if hasattr(v.vulnerability, 'cve') else "N/A",
                        severity=v.vulnerability.severity,
                        description=v.vulnerability.details[0].description,
                    )
                    for v in vulnerabilities
                ]
                return models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Live scan found {len(vuln_data)} vulnerabilities in image {resource_url}.",
                    vulnerabilities=vuln_data,
                )

                # --- MEMORY INTEGRATION: Save new result to memory ---
                response_obj = models.GcpWorkloadSecurityResponse(success=True, message=message, vulnerabilities=vuln_data)
                memory.add_container_scan_result(resource_url, vuln_data, response_obj.message)
                return response_obj
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred while scanning container image: {e}",
                )

        elif "analyze firewall rules for project" in instruction or "analyze overly permissive firewall rules" in instruction:
            project_id = instruction.split("analyze firewall rules for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            client = clients.GcpWorkloadClient(project_id)
            try:
                rules_raw = client.list_firewall_rules()
                analysis_results = []
                sensitive_ports = {
                    "22": "SSH",
                    "3389": "RDP",
                    "23": "Telnet",
                    "3306": "MySQL",
                    "5432": "PostgreSQL",
                }

                for rule in rules_raw:
                    if "0.0.0.0/0" in rule.source_ranges and rule.direction == "INGRESS":
                        for allowed in rule.allowed:
                            if allowed.ports:
                                for port in allowed.ports:
                                    if port in sensitive_ports:
                                        analysis_results.append(
                                            models.FirewallAnalysis(
                                                name=rule.name,
                                                message=f"Firewall rule '{rule.name}' allows unrestricted access to port {port} ({sensitive_ports[port]}) from the internet.",
                                                recommended_action=f"Restrict the source ranges for this rule to specific IP addresses or ranges instead of '0.0.0.0/0'.",
                                            )
                                        )

                return models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"Firewall analysis complete. Found {len(analysis_results)} potential issues.",
                    firewall_analysis=analysis_results,
                )
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred during firewall analysis: {e}",
                )

        elif "analyze iam policy for project" in instruction:
            project_id = instruction.split("analyze iam policy for project")[-1].strip()
            if not project_id:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message="Project ID not provided in the instruction.",
                )

            client = clients.GcpWorkloadClient(project_id)
            try:
                policy_raw = client.get_iam_policy()
                analysis_results = []
                overly_permissive_roles = ["roles/owner", "roles/editor"]

                for binding in policy_raw.bindings:
                    if binding.role in overly_permissive_roles:
                        for member in binding.members:
                            analysis_results.append(
                                models.IamAnalysis(
                                    member=member,
                                    role=binding.role,
                                    message=f"Member '{member}' has an overly permissive role '{binding.role}'.",
                                    recommended_action="Follow the principle of least privilege. Assign more granular roles instead of primitive roles like Owner or Editor.",
                                )
                            )

                return models.GcpWorkloadSecurityResponse(
                    success=True,
                    message=f"IAM policy analysis complete. Found {len(analysis_results)} potential issues.",
                    iam_analysis=analysis_results,
                )
            except Exception as e:
                return models.GcpWorkloadSecurityResponse(
                    success=False,
                    message=f"An error occurred during IAM policy analysis: {e}",
                )

        return models.GcpWorkloadSecurityResponse(
            success=False,
            message="Instruction not understood. Please use 'list gce instances for project <project_id>' or 'scan container image <resource_url> for project <project_id>'.",
        )
