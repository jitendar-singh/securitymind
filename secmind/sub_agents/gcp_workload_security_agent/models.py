from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class Vulnerability(BaseModel):
    """
    A model for a single vulnerability.
    """
    cve: str
    severity: str
    description: str

class GceNetworkInterface(BaseModel):
    name: str
    network: str
    network_ip: str
    access_configs: List[Dict[str, Any]] = []

class GceServiceAccount(BaseModel):
    email: str
    scopes: List[str]

class GceInstanceDetails(BaseModel):
    """
    A model for detailed GCE instance information.
    """
    name: str
    machine_type: str
    status: str
    zone: str
    service_accounts: List[GceServiceAccount]
    network_interfaces: List[GceNetworkInterface]
    labels: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None
    firewall_rules: Optional[List['FirewallRule']] = None

class GkeCluster(BaseModel):
    """
    A model for a GKE cluster.
    """
    name: str
    location: str
    status: str
    current_master_version: str
    private_cluster: bool
    datapath_provider: str
    network: str

class CloudRunService(BaseModel):
    """
    A model for a Cloud Run service.
    """
    name: str
    location: str
    uri: str
    creator: str
    last_modifier: str
    ingress: str
    launch_stage: str

class CloudFunction(BaseModel):
    """
    A model for a Cloud Function.
    """
    name: str
    location: str
    state: str
    runtime: str
    environment: str
    https_trigger_url: Optional[str] = None
    service_account: str
    update_time: str

class FirewallRuleAllowed(BaseModel):
    ip_protocol: str
    ports: Optional[List[str]] = None

class FirewallRule(BaseModel):
    """
    A model for a Firewall rule.
    """
    name: str
    description: Optional[str] = None
    network: str
    direction: str
    priority: int
    source_ranges: List[str]
    destination_ranges: List[str]
    allowed: List[FirewallRuleAllowed]
    denied: List[FirewallRuleAllowed]
    disabled: bool

class IamPolicyBinding(BaseModel):
    role: str
    members: List[str]

class IamPolicy(BaseModel):
    """
    A model for an IAM policy.
    """
    version: int
    bindings: List[IamPolicyBinding]
    etag: str

class FirewallAnalysis(BaseModel):
    """
    A model for firewall rule analysis.
    """
    name: str
    message: str
    recommended_action: str

class IamAnalysis(BaseModel):
    """
    A model for IAM policy analysis.
    """
    member: str
    role: str
    message: str
    recommended_action: str

class GcpWorkloadSecurityResponse(BaseModel):
    """
    A response from the GCP Workload Security Agent.
    """
    success: bool
    message: str
    data: Optional[List[str]] = None
    vulnerabilities: Optional[List[Vulnerability]] = None
    resource_details: Optional[GceInstanceDetails] = None
    gke_clusters: Optional[List[GkeCluster]] = None
    cloud_run_services: Optional[List[CloudRunService]] = None
    cloud_functions: Optional[List[CloudFunction]] = None
    firewall_rules: Optional[List[FirewallRule]] = None
    iam_policy: Optional[IamPolicy] = None
    firewall_analysis: Optional[List[FirewallAnalysis]] = None
    iam_analysis: Optional[List[IamAnalysis]] = None
