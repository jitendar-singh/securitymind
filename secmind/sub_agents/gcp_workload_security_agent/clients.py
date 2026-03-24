# secmind/sub_agents/gcp_workload_security_agent/clients.py

from google.cloud import compute_v1
from google.cloud import container_v1
from google.cloud import run_v2
from google.cloud import functions_v2
from google.cloud import resourcemanager_v3
from google.cloud.devtools import containeranalysis_v1
from grafeas.grafeas_v1.services.grafeas import client as grafeas_client

class GcpWorkloadClient:
    """
    A client for interacting with GCP workload APIs.
    """

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.grafeas_client = grafeas_client.GrafeasClient()

    def list_gce_instances(self):
        """
        Lists all GCE instances in the project.
        """
        client = compute_v1.InstancesClient()
        request = compute_v1.AggregatedListInstancesRequest(
            project=self.project_id,
        )
        instances = []
        for zone, response in client.aggregated_list(request=request):
            if response.instances:
                instances.extend(response.instances)
        return instances

    def get_gce_instance_details(self, instance: str, zone: str):
        """
        Gets detailed information about a specific GCE instance.

        Args:
            instance: The name of the GCE instance.
            zone: The zone where the instance is located.

        Returns:
            A dictionary containing the instance details.
        """
        client = compute_v1.InstancesClient()
        request = compute_v1.GetInstanceRequest(
            project=self.project_id,
            zone=zone,
            instance=instance,
        )
        return client.get(request=request)

    def list_gke_clusters(self):
        """
        Lists all GKE clusters in the project.
        """
        client = container_v1.ClusterManagerClient()
        parent = f"projects/{self.project_id}/locations/-"
        request = container_v1.ListClustersRequest(parent=parent)
        return client.list_clusters(request=request).clusters

    def list_cloud_run_services(self):
        """
        Lists all Cloud Run services in the project.
        """
        client = run_v2.ServicesClient()
        parent = f"projects/{self.project_id}/locations/-"
        request = run_v2.ListServicesRequest(parent=parent)
        return client.list_services(request=request)

    def list_cloud_functions(self):
        """
        Lists all Cloud Functions in the project.
        """
        client = functions_v2.FunctionServiceClient()
        parent = f"projects/{self.project_id}/locations/-"
        request = functions_v2.ListFunctionsRequest(parent=parent)
        return client.list_functions(request=request)

    def list_firewall_rules(self):
        """
        Lists all firewall rules in the project.
        """
        client = compute_v1.FirewallsClient()
        request = compute_v1.ListFirewallsRequest(
            project=self.project_id,
        )
        return client.list(request=request)

    def get_iam_policy(self):
        """
        Gets the IAM policy for the project.
        """
        client = resourcemanager_v3.ProjectsClient()
        request = resourcemanager_v3.GetIamPolicyRequest(
            resource=f"projects/{self.project_id}",
        )
        return client.get_iam_policy(request=request)

    def get_container_vulnerabilities(self, resource_url: str):
        """
        Gets vulnerability occurrences for a container image.

        Args:
            resource_url: The URL of the container image.

        Returns:
            A list of vulnerability occurrences.
        """
        filter_str = f'kind="VULNERABILITY" AND resource_url="{resource_url}"'
        return self.grafeas_client.list_occurrences(
            parent=f"projects/{self.project_id}", filter=filter_str
        )
