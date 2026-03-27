"""
MemoryManager for the SecurityMind agent.

This module provides a hybrid memory system using SQLite for structured data
and ChromaDB for semantic/vector-based search.
"""
import logging
import sqlite3
import chromadb
import json
import uuid
import os
import hashlib
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MemoryManager:
    """
    Manages the agent's long-term memory using a hybrid database approach.

    - SQLite: Stores structured, factual data (e.g., CVE triage results) for
              fast, exact lookups.
    - ChromaDB: Stores unstructured text summaries for semantic search to find
                contextually relevant past interactions.
    """

    def __init__(self, db_path: str = "memory"):
        """
        Initializes the MemoryManager and sets up database connections.

        Args:
            db_path (str): The directory to store database files.
        """
        # --- Create the directory if it doesn't exist ---
        os.makedirs(db_path, exist_ok=True)
        
        # --- SQLite Setup for structured data ---
        self.sqlite_conn = sqlite3.connect(f"{db_path}/structured_memory.db", check_same_thread=False)
        self.sqlite_conn.row_factory = sqlite3.Row
        self._setup_sqlite()

        # --- ChromaDB Setup for semantic search ---
        self.chroma_client = chromadb.PersistentClient(path=f"{db_path}/vector_memory")
        self.semantic_collection = self.chroma_client.get_or_create_collection(
            name="interaction_summaries"
        )

    def _setup_sqlite(self):
        """Creates the necessary tables in the SQLite database if they don't exist."""
        cursor = self.sqlite_conn.cursor()
        # Table for storing detailed vulnerability triage results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS triage_results (
                cve_id TEXT PRIMARY KEY,
                severity TEXT,
                recommendation TEXT,
                details_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing GCP container scan results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS gcp_container_scan_results (
                resource_url TEXT PRIMARY KEY,
                vulnerabilities_json TEXT,
                message TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing threat models
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_models (
                app_details_hash TEXT PRIMARY KEY,
                report_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing code reviews
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_reviews (
                code_hash TEXT PRIMARY KEY,
                review_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing cloud resources
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_resources (
                cache_key TEXT PRIMARY KEY,
                resources_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing security posture
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_posture (
                cache_key TEXT PRIMARY KEY,
                posture_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing IAM recommendations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iam_recommendations (
                project_id TEXT PRIMARY KEY,
                recommendations_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing organization policies
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS org_policies (
                organization_id TEXT PRIMARY KEY,
                policies_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing access keys
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_keys (
                cache_key TEXT PRIMARY KEY,
                keys_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing GCE instances
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS gce_instances (
                project_id TEXT PRIMARY KEY,
                instances_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing GKE clusters
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS gke_clusters (
                project_id TEXT PRIMARY KEY,
                clusters_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing Cloud Run services
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_run_services (
                project_id TEXT PRIMARY KEY,
                services_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing Cloud Functions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_functions (
                project_id TEXT PRIMARY KEY,
                functions_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing firewall rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS firewall_rules (
                project_id TEXT PRIMARY KEY,
                rules_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing IAM policies
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iam_policies (
                project_id TEXT PRIMARY KEY,
                policy_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing GCE instance details
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS gce_instance_details (
                cache_key TEXT PRIMARY KEY,
                details_json TEXT,
                timestamp DATETIME
            )
        """)
        # Table for storing public GCS buckets
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS public_gcs_buckets (
                project_id TEXT PRIMARY KEY,
                buckets_json TEXT,
                timestamp DATETIME
            )
        """)
        self.sqlite_conn.commit()

    def add_triage_result(self, cve_id: str, severity: str, recommendation: str, details: dict):
        """
        Adds a new vulnerability triage result to both SQLite and ChromaDB.

        Args:
            cve_id (str): The CVE identifier (e.g., "CVE-2023-4863").
            severity (str): The assessed severity (e.g., "CRITICAL", "HIGH").
            recommendation (str): The remediation advice.
            details (dict): The full details dictionary from the triage tool.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        # 1. Add structured data to SQLite
        cursor.execute(
            """
            INSERT OR REPLACE INTO triage_results (cve_id, severity, recommendation, details_json, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (cve_id, severity, recommendation, json.dumps(details), timestamp)
        )
        self.sqlite_conn.commit()

        # 2. Create a summary and add it to ChromaDB for semantic search
        summary_text = (
            f"On {timestamp.strftime('%Y-%m-%d')}, a triage was performed for {cve_id}. "
            f"The severity was determined to be {severity}. "
            f"The recommendation is: '{recommendation}'. "
            f"Description: {details.get('description', 'No description available.')}"
        )

        self.semantic_collection.add(
            documents=[summary_text],
            metadatas=[{"cve_id": cve_id, "source": "vuln_triage_agent"}],
            ids=[str(uuid.uuid4())] # Use a unique ID for each entry
        )

    def get_triage_result(self, cve_id: str) -> dict | None:
        """
        Retrieves a specific triage result from SQLite using the exact CVE ID.

        Args:
            cve_id (str): The CVE identifier to look up.

        Returns:
            A dictionary with the stored data, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT * FROM triage_results WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()

        if row:
            result = dict(row)
            result['details'] = json.loads(result.pop('details_json'))
            return result
        return None

    def add_container_scan_result(self, resource_url: str, vulnerabilities: list, message: str):
        """
        Adds a new GCP container scan result to the memory.

        Args:
            resource_url (str): The full URL of the container image.
            vulnerabilities (list): The list of vulnerability models.
            message (str): The summary message.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        # 1. Add structured data to SQLite
        vulnerabilities_dict = [vuln.model_dump() for vuln in vulnerabilities]
        cursor.execute(
            """
            INSERT OR REPLACE INTO gcp_container_scan_results (resource_url, vulnerabilities_json, message, timestamp)
            VALUES (?, ?, ?, ?)
            """,
            (resource_url, json.dumps(vulnerabilities_dict), message, timestamp)
        )
        self.sqlite_conn.commit()

        # 2. Create a summary and add it to ChromaDB for semantic search
        summary_text = (
            f"On {timestamp.strftime('%Y-%m-%d')}, a container scan was performed for image {resource_url}. "
            f"{message}"
        )

        self.semantic_collection.add(
            documents=[summary_text],
            metadatas=[{"resource_url": resource_url, "source": "gcp_workload_security_agent"}],
            ids=[str(uuid.uuid4())]
        )

    def get_container_scan_result(self, resource_url: str) -> dict | None:
        """
        Retrieves a cached container scan result from SQLite.

        Args:
            resource_url (str): The container image URL to look up.

        Returns:
            A dictionary with the stored data, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT * FROM gcp_container_scan_results WHERE resource_url = ?", (resource_url,))
        row = cursor.fetchone()

        if row:
            result = {
                "success": True,
                "message": row["message"],
                "vulnerabilities": json.loads(row["vulnerabilities_json"])
            }
            return result
        return None

    def add_threat_model(self, app_details: dict, report: dict):
        """
        Adds a new threat model report to the cache.

        Args:
            app_details (dict): The application details dictionary.
            report (dict): The threat model report.
        """
        app_details_str = json.dumps(app_details, sort_keys=True)
        app_details_hash = hashlib.sha256(app_details_str.encode('utf-8')).hexdigest()
        
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO threat_models (app_details_hash, report_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (app_details_hash, json.dumps(report), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Threat model cached with hash: {app_details_hash}")

    def get_threat_model(self, app_details: dict) -> dict | None:
        """
        Retrieves a cached threat model report.

        Args:
            app_details (dict): The application details dictionary.

        Returns:
            The cached report, or None if not found.
        """
        app_details_str = json.dumps(app_details, sort_keys=True)
        app_details_hash = hashlib.sha256(app_details_str.encode('utf-8')).hexdigest()

        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT report_json FROM threat_models WHERE app_details_hash = ?", (app_details_hash,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Threat model cache hit with hash: {app_details_hash}")
            return json.loads(row['report_json'])
        
        logger.info(f"Threat model cache miss for hash: {app_details_hash}")
        return None

    def add_code_review(self, code_snippet: str, review: dict):
        """
        Adds a new code review to the cache.

        Args:
            code_snippet (str): The code snippet that was reviewed.
            review (dict): The review of the code.
        """
        code_hash = hashlib.sha256(code_snippet.encode('utf-8')).hexdigest()
        
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO code_reviews (code_hash, review_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (code_hash, json.dumps(review), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Code review cached with hash: {code_hash}")

    def get_code_review(self, code_snippet: str) -> dict | None:
        """
        Retrieves a cached code review.

        Args:
            code_snippet (str): The code snippet to look up.

        Returns:
            The cached review, or None if not found.
        """
        code_hash = hashlib.sha256(code_snippet.encode('utf-8')).hexdigest()

        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT review_json FROM code_reviews WHERE code_hash = ?", (code_hash,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Code review cache hit with hash: {code_hash}")
            return json.loads(row['review_json'])
        
        logger.info(f"Code review cache miss for hash: {code_hash}")
        return None

    def add_cloud_resources(self, scope: str, resource_types: list[str] | None, resources: dict):
        """
        Adds cloud resources to the cache.

        Args:
            scope (str): The scope of the query.
            resource_types (list[str] | None): The resource types of the query.
            resources (dict): The resources to cache.
        """
        key_str = f"{scope}-{resource_types}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()
        
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO cloud_resources (cache_key, resources_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (cache_key, json.dumps(resources), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Cloud resources cached with key: {cache_key}")

    def get_cloud_resources(self, scope: str, resource_types: list[str] | None) -> dict | None:
        """
        Retrieves cached cloud resources.

        Args:
            scope (str): The scope of the query.
            resource_types (list[str] | None): The resource types of the query.

        Returns:
            The cached resources, or None if not found.
        """
        key_str = f"{scope}-{resource_types}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()

        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT resources_json FROM cloud_resources WHERE cache_key = ?", (cache_key,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Cloud resources cache hit with key: {cache_key}")
            return json.loads(row['resources_json'])
        
        logger.info(f"Cloud resources cache miss for key: {cache_key}")
        return None

    def add_security_posture(self, parent: str, source_id: str | None, posture: dict):
        """
        Adds security posture to the cache.

        Args:
            parent (str): The parent of the query.
            source_id (str | None): The source ID of the query.
            posture (dict): The posture to cache.
        """
        key_str = f"{parent}-{source_id}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()
        
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO security_posture (cache_key, posture_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (cache_key, json.dumps(posture), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Security posture cached with key: {cache_key}")

    def get_security_posture(self, parent: str, source_id: str | None) -> dict | None:
        """
        Retrieves cached security posture.

        Args:
            parent (str): The parent of the query.
            source_id (str | None): The source ID of the query.

        Returns:
            The cached posture, or None if not found.
        """
        key_str = f"{parent}-{source_id}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()

        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT posture_json FROM security_posture WHERE cache_key = ?", (cache_key,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Security posture cache hit with key: {cache_key}")
            return json.loads(row['posture_json'])
        
        logger.info(f"Security posture cache miss for key: {cache_key}")
        return None

    def add_iam_recommendations(self, project_id: str, recommendations: dict):
        """
        Adds IAM recommendations to the cache.

        Args:
            project_id (str): The project ID of the query.
            recommendations (dict): The recommendations to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO iam_recommendations (project_id, recommendations_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(recommendations), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"IAM recommendations cached for project: {project_id}")

    def get_iam_recommendations(self, project_id: str) -> dict | None:
        """
        Retrieves cached IAM recommendations.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached recommendations, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT recommendations_json FROM iam_recommendations WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"IAM recommendations cache hit for project: {project_id}")
            return json.loads(row['recommendations_json'])
        
        logger.info(f"IAM recommendations cache miss for project: {project_id}")
        return None

    def add_org_policies(self, organization_id: str, policies: dict):
        """
        Adds organization policies to the cache.

        Args:
            organization_id (str): The organization ID of the query.
            policies (dict): The policies to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO org_policies (organization_id, policies_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (organization_id, json.dumps(policies), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Organization policies cached for organization: {organization_id}")

    def get_org_policies(self, organization_id: str) -> dict | None:
        """
        Retrieves cached organization policies.

        Args:
            organization_id (str): The organization ID of the query.

        Returns:
            The cached policies, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT policies_json FROM org_policies WHERE organization_id = ?", (organization_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Organization policies cache hit for organization: {organization_id}")
            return json.loads(row['policies_json'])
        
        logger.info(f"Organization policies cache miss for organization: {organization_id}")
        return None

    def add_access_keys(self, project_id: str, max_age_days: int, keys: dict):
        """
        Adds access keys to the cache.

        Args:
            project_id (str): The project ID of the query.
            max_age_days (int): The max age days of the query.
            keys (dict): The keys to cache.
        """
        key_str = f"{project_id}-{max_age_days}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()
        
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO access_keys (cache_key, keys_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (cache_key, json.dumps(keys), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Access keys cached with key: {cache_key}")

    def get_access_keys(self, project_id: str, max_age_days: int) -> dict | None:
        """
        Retrieves cached access keys.

        Args:
            project_id (str): The project ID of the query.
            max_age_days (int): The max age days of the query.

        Returns:
            The cached keys, or None if not found.
        """
        key_str = f"{project_id}-{max_age_days}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()

        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT keys_json FROM access_keys WHERE cache_key = ?", (cache_key,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Access keys cache hit with key: {cache_key}")
            return json.loads(row['keys_json'])
        
        logger.info(f"Access keys cache miss for key: {cache_key}")
        return None

    def add_gce_instances(self, project_id: str, instances: dict):
        """
        Adds GCE instances to the cache.

        Args:
            project_id (str): The project ID of the query.
            instances (dict): The instances to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO gce_instances (project_id, instances_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(instances), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"GCE instances cached for project: {project_id}")

    def get_gce_instances(self, project_id: str) -> dict | None:
        """
        Retrieves cached GCE instances.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached instances, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT instances_json FROM gce_instances WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"GCE instances cache hit for project: {project_id}")
            return json.loads(row['instances_json'])
        
        logger.info(f"GCE instances cache miss for project: {project_id}")
        return None

    def add_gke_clusters(self, project_id: str, clusters: dict):
        """
        Adds GKE clusters to the cache.

        Args:
            project_id (str): The project ID of the query.
            clusters (dict): The clusters to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO gke_clusters (project_id, clusters_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(clusters), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"GKE clusters cached for project: {project_id}")

    def get_gke_clusters(self, project_id: str) -> dict | None:
        """
        Retrieves cached GKE clusters.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached clusters, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT clusters_json FROM gke_clusters WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"GKE clusters cache hit for project: {project_id}")
            return json.loads(row['clusters_json'])
        
        logger.info(f"GKE clusters cache miss for project: {project_id}")
        return None

    def add_cloud_run_services(self, project_id: str, services: dict):
        """
        Adds Cloud Run services to the cache.

        Args:
            project_id (str): The project ID of the query.
            services (dict): The services to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO cloud_run_services (project_id, services_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(services), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Cloud Run services cached for project: {project_id}")

    def get_cloud_run_services(self, project_id: str) -> dict | None:
        """
        Retrieves cached Cloud Run services.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached services, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT services_json FROM cloud_run_services WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Cloud Run services cache hit for project: {project_id}")
            return json.loads(row['services_json'])
        
        logger.info(f"Cloud Run services cache miss for project: {project_id}")
        return None

    def add_cloud_functions(self, project_id: str, functions: dict):
        """
        Adds Cloud Functions to the cache.

        Args:
            project_id (str): The project ID of the query.
            functions (dict): The functions to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO cloud_functions (project_id, functions_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(functions), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Cloud Functions cached for project: {project_id}")

    def get_cloud_functions(self, project_id: str) -> dict | None:
        """
        Retrieves cached Cloud Functions.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached functions, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT functions_json FROM cloud_functions WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Cloud Functions cache hit for project: {project_id}")
            return json.loads(row['functions_json'])
        
        logger.info(f"Cloud Functions cache miss for project: {project_id}")
        return None

    def add_firewall_rules(self, project_id: str, rules: dict):
        """
        Adds firewall rules to the cache.

        Args:
            project_id (str): The project ID of the query.
            rules (dict): The rules to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO firewall_rules (project_id, rules_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(rules), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Firewall rules cached for project: {project_id}")

    def get_firewall_rules(self, project_id: str) -> dict | None:
        """
        Retrieves cached firewall rules.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached rules, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT rules_json FROM firewall_rules WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Firewall rules cache hit for project: {project_id}")
            return json.loads(row['rules_json'])
        
        logger.info(f"Firewall rules cache miss for project: {project_id}")
        return None

    def add_iam_policy(self, project_id: str, policy: dict):
        """
        Adds IAM policy to the cache.

        Args:
            project_id (str): The project ID of the query.
            policy (dict): The policy to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO iam_policies (project_id, policy_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(policy), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"IAM policy cached for project: {project_id}")

    def get_iam_policy(self, project_id: str) -> dict | None:
        """
        Retrieves cached IAM policy.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached policy, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT policy_json FROM iam_policies WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"IAM policy cache hit for project: {project_id}")
            return json.loads(row['policy_json'])
        
        logger.info(f"IAM policy cache miss for project: {project_id}")
        return None

    def add_gce_instance_details(self, project_id: str, instance_name: str, zone: str, details: dict):
        """
        Adds GCE instance details to the cache.

        Args:
            project_id (str): The project ID of the query.
            instance_name (str): The instance name of the query.
            zone (str): The zone of the query.
            details (dict): The details to cache.
        """
        key_str = f"{project_id}-{instance_name}-{zone}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()
        
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO gce_instance_details (cache_key, details_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (cache_key, json.dumps(details), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"GCE instance details cached with key: {cache_key}")

    def get_gce_instance_details(self, project_id: str, instance_name: str, zone: str) -> dict | None:
        """
        Retrieves cached GCE instance details.

        Args:
            project_id (str): The project ID of the query.
            instance_name (str): The instance name of the query.
            zone (str): The zone of the query.

        Returns:
            The cached details, or None if not found.
        """
        key_str = f"{project_id}-{instance_name}-{zone}"
        cache_key = hashlib.sha256(key_str.encode('utf-8')).hexdigest()

        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT details_json FROM gce_instance_details WHERE cache_key = ?", (cache_key,))
        row = cursor.fetchone()

        if row:
            logger.info(f"GCE instance details cache hit with key: {cache_key}")
            return json.loads(row['details_json'])
        
        logger.info(f"GCE instance details cache miss for key: {cache_key}")
        return None

    def add_public_gcs_buckets(self, project_id: str, buckets: dict):
        """
        Adds public GCS buckets to the cache.

        Args:
            project_id (str): The project ID of the query.
            buckets (dict): The buckets to cache.
        """
        cursor = self.sqlite_conn.cursor()
        timestamp = datetime.now(timezone.utc)

        cursor.execute(
            """
            INSERT OR REPLACE INTO public_gcs_buckets (project_id, buckets_json, timestamp)
            VALUES (?, ?, ?)
            """,
            (project_id, json.dumps(buckets), timestamp)
        )
        self.sqlite_conn.commit()
        logger.info(f"Public GCS buckets cached for project: {project_id}")

    def get_public_gcs_buckets(self, project_id: str) -> dict | None:
        """
        Retrieves cached public GCS buckets.

        Args:
            project_id (str): The project ID of the query.

        Returns:
            The cached buckets, or None if not found.
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT buckets_json FROM public_gcs_buckets WHERE project_id = ?", (project_id,))
        row = cursor.fetchone()

        if row:
            logger.info(f"Public GCS buckets cache hit for project: {project_id}")
            return json.loads(row['buckets_json'])

        logger.info(f"Public GCS buckets cache miss for project: {project_id}")
        return None

    def search_semantic_memory(self, query_text: str, n_results: int = 2) -> list[str]:
        """
        Searches the semantic memory in ChromaDB for contextually relevant information.

        Args:
            query_text (str): The user's query or a summary of the current context.
            n_results (int): The number of relevant results to return.

        Returns:
            A list of the most relevant document summaries.
        """
        results = self.semantic_collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        return results['documents'][0] if results and results['documents'] else []