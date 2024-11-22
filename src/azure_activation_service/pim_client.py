import requests
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from azure.identity import AzureCliCredential
from azure.core.exceptions import ClientAuthenticationError


@dataclass
class Role:
    """Represents an Azure PIM role."""
    id: str
    name: str
    scope: str
    display_name: str
    resource_name: str
    resource_type: str
    role_definition_id: str
    role_eligibility_schedule_id: str
    principal_id: str
    assignment_name: Optional[str] = None
    assignment_type: Optional[str] = None
    start_date_time: Optional[datetime] = None
    end_date_time: Optional[datetime] = None

    def __str__(self) -> str:
        """String representation of the role with its status."""
        status = "ACTIVATED" if self.assignment_type else "NOT ACTIVATED"
        expiry = f" (expires: {self.end_date_time})" if self.end_date_time else ""
        return (f"Role: {self.display_name}\n"
                f"Resource: {self.resource_name} ({self.resource_type})\n"
                f"Status: {status}{expiry}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert the role to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'scope': self.scope,
            'display_name': self.display_name,
            'resource_name': self.resource_name,
            'resource_type': self.resource_type,
            'role_definition_id': self.role_definition_id,
            'role_eligibility_schedule_id': self.role_eligibility_schedule_id,
            'principal_id': self.principal_id,
            'assignment_name': self.assignment_name,
            'assignment_type': self.assignment_type,
            'start_date_time': self.start_date_time.isoformat() if self.start_date_time else None,
            'end_date_time': self.end_date_time.isoformat() if self.end_date_time else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Role':
        """Create a Role object from a dictionary."""
        return cls(
            id=data['id'],
            name=data['name'],
            scope=data['scope'],
            display_name=data['display_name'],
            resource_name=data['resource_name'],
            resource_type=data['resource_type'],
            role_definition_id=data['role_definition_id'],
            role_eligibility_schedule_id=data['role_eligibility_schedule_id'],
            principal_id=data['principal_id'],
            assignment_name=data['assignment_name'],
            assignment_type=data['assignment_type'],
            start_date_time=datetime.fromisoformat(data['start_date_time']) if data['start_date_time'] else None,
            end_date_time=datetime.fromisoformat(data['end_date_time']) if data['end_date_time'] else None
        )


class PIMError(Exception):
    """Base exception for PIM-related errors."""
    pass


class NotAuthenticatedError(PIMError):
    """Raised when user is not authenticated with Azure."""
    pass


class PIMClient:
    """Client for managing Azure PIM roles."""

    AZURE_MGMT_URL = "https://management.azure.com"
    API_VERSION = "2020-10-01"

    def __init__(self):
        """Initialize PIM client using AzureCliCredential."""
        self.credential = AzureCliCredential()
        self._update_token()

    def _update_token(self):
        """Update the access token using AzureCliCredential."""
        try:
            token = self.credential.get_token(
                "https://management.azure.com/.default")
            self.headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
        except ClientAuthenticationError as e:
            raise NotAuthenticatedError(
                "Failed to get Azure token. Please run 'az login' first.") from e

    def get_roles(self) -> List[Role]:
        """
        Query all PIM roles for the current user and their activation status.

        Returns:
            List[Role]: List of available roles and their status

        Raises:
            NotAuthenticatedError: If not authenticated with Azure
            PIMError: If the API request fails
        """
        # Make batch request for both role eligibility and assignments
        batch_request = {
            "requests": [
                {
                    "httpMethod": "GET",
                    "relativeUrl": f"/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version={self.API_VERSION}&$filter=asTarget()"
                },
                {
                    "httpMethod": "GET",
                    "relativeUrl": f"/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version={self.API_VERSION}&$filter=asTarget()"
                }
            ]
        }

        response = requests.post(
            f"{self.AZURE_MGMT_URL}/batch?api-version=2020-06-01",
            headers=self.headers,
            json=batch_request
        )

        if response.status_code == 401:
            # Token might have expired, try to refresh it
            self._update_token()
            response = requests.post(
                f"{self.AZURE_MGMT_URL}/batch?api-version=2020-06-01",
                headers=self.headers,
                json=batch_request
            )

        if response.status_code != 200:
            raise PIMError(f"Failed to get roles: {response.text}")

        data = response.json()
        roles = []

        # Process eligibility responses
        eligibilities = data['responses'][0]['content']['value']
        assignments = data['responses'][1]['content']['value']

        for eligibility in eligibilities:
            props = eligibility['properties']
            exp_props = props['expandedProperties']

            role = Role(
                id=eligibility['id'],
                name=eligibility['name'],
                scope=props['scope'],
                display_name=exp_props['roleDefinition']['displayName'],
                resource_name=exp_props['scope']['displayName'],
                resource_type=exp_props['scope']['type'],
                role_definition_id=props['roleDefinitionId'],
                role_eligibility_schedule_id=props['roleEligibilityScheduleId'],
                principal_id=props['principalId']
            )

            # Check if role is currently activated
            role_assignment = next(
                (ra for ra in assignments
                 if ra['properties']['linkedRoleEligibilityScheduleInstanceId'] == role.id),
                None
            )

            if role_assignment:
                props = role_assignment['properties']
                role.assignment_name = role_assignment['name']
                role.assignment_type = props['assignmentType']
                # Handle Azure's datetime format which might have single-digit milliseconds

                def parse_azure_datetime(dt_str: str) -> datetime:
                    # Replace 'Z' with '+00:00' for UTC
                    dt_str = dt_str.replace('Z', '+00:00')
                    # Ensure milliseconds have 6 digits (microseconds)
                    if '.' in dt_str:
                        base, ms = dt_str.split('.')
                        ms, tz = ms.split('+')
                        # Pad milliseconds to 6 digits
                        ms = ms.ljust(6, '0')
                        dt_str = f"{base}.{ms}+{tz}"
                    return datetime.fromisoformat(dt_str)

                role.start_date_time = parse_azure_datetime(
                    props['startDateTime'])
                role.end_date_time = parse_azure_datetime(props['endDateTime'])

            roles.append(role)

        return roles

    def _get_user_id(self) -> str:
        """Get the current signed-in user's ID using Microsoft Graph API."""
        graph_token = self.credential.get_token(
            "https://graph.microsoft.com/.default").token
        headers = {"Authorization": f"Bearer {graph_token}"}

        response = requests.get(
            "https://graph.microsoft.com/v1.0/me", headers=headers)

        if response.status_code != 200:
            raise PIMError(f"Failed to get user ID: {response.text}")

        return response.json()['id']

    def activate_role(self, role: Role, justification: str = "PIM role activation via Python SDK") -> Dict[str, Any]:
        """
        Activate a specific PIM role.

        Args:
            role: The role to activate
            justification: Reason for activation

        Returns:
            Dict[str, Any]: Activation response from the API

        Raises:
            NotAuthenticatedError: If not authenticated with Azure
            PIMError: If the activation request fails
        """
        # Get user ID and role policy in parallel
        user_id = self._get_user_id()  # Get user ID from Graph API

        policy_response = requests.get(
            f"{self.AZURE_MGMT_URL}{role.scope}/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01&$filter=roleDefinitionId eq '{role.role_definition_id}'",
            headers=self.headers
        )

        if policy_response.status_code == 401:
            self._update_token()
            policy_response = requests.get(
                f"{self.AZURE_MGMT_URL}{role.scope}/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01&$filter=roleDefinitionId eq '{role.role_definition_id}'",
                headers=self.headers
            )

        if policy_response.status_code != 200:
            raise PIMError(
                f"Failed to get role policy: {policy_response.text}")

        policy_data = policy_response.json()

        # Extract maximum duration from policy
        max_duration = next(
            (rule['maximumDuration']
             for rule in policy_data['value'][0]['properties']['effectiveRules']
             if rule['id'] == 'Expiration_EndUser_Assignment'),
            None
        )

        # Extract maximum duration from policy
        max_duration = next(
            (rule['maximumDuration']
             for rule in policy_data['value'][0]['properties']['effectiveRules']
             if rule['id'] == 'Expiration_EndUser_Assignment'),
            None
        )

        # Prepare and send activation request
        activation_request = {
            "properties": {
                "principalId": user_id,  # Use the current user's ID instead of role.principal_id
                "requestType": "SelfActivate",
                "roleDefinitionId": role.role_definition_id,
                "linkedRoleEligibilityScheduleId": role.role_eligibility_schedule_id,
                "justification": justification,
                "scheduleInfo": {
                    "expiration": {
                        "type": "AfterDuration",
                        "duration": max_duration
                    }
                }
            }
        }

        activation_url = (f"{self.AZURE_MGMT_URL}{role.scope}/providers/Microsoft.Authorization/"
                          f"roleAssignmentScheduleRequests/{str(uuid.uuid4())}?api-version={self.API_VERSION}")

        response = requests.put(
            activation_url,
            headers=self.headers,
            json=activation_request
        )

        if response.status_code not in (200, 201):
            raise PIMError(f"Failed to activate role: {response.text}")

        return response.json()

    def deactivate_role(self, role: Role, justification: str = "PIM role deactivation via Python SDK") -> Dict[str, Any]:
        """
        Deactivate a specific PIM role.

        Args:
            role: The role to deactivate
            justification: Reason for deactivation

        Returns:
            Dict[str, Any]: Deactivation response from the API

        Raises:
            NotAuthenticatedError: If not authenticated with Azure
            PIMError: If the deactivation request fails
        """
        deactivation_request = {
            "properties": {
                "principalId": self._get_user_id(),  # Use the current user's ID
                "requestType": "SelfDeactivate",
                "roleDefinitionId": role.role_definition_id,
                "linkedRoleEligibilityScheduleId": role.role_eligibility_schedule_id,
                "justification": justification
            }
        }

        deactivation_url = (f"{self.AZURE_MGMT_URL}{role.scope}/providers/Microsoft.Authorization/"
                            f"roleAssignmentScheduleRequests/{str(uuid.uuid4())}?api-version={self.API_VERSION}")

        response = requests.put(
            deactivation_url,
            headers=self.headers,
            json=deactivation_request
        )

        if response.status_code == 401:
            self._update_token()
            response = requests.put(
                deactivation_url,
                headers=self.headers,
                json=deactivation_request
            )

        if response.status_code not in (200, 201):
            raise PIMError(f"Failed to deactivate role: {response.text}")

        return response.json()

    def serialize_roles(self, roles):
        """Convert Role objects to dictionary for caching"""
        return [role.to_dict() for role in roles]

    def deserialize_roles(self, data):
        """Convert cached dictionary back to Role objects"""
        return [Role.from_dict(role_data) for role_data in data]


def main():
    """Example usage of the PIMClient."""
    try:
        # Initialize PIM client
        pim = PIMClient()

        # Get all roles
        print("Fetching PIM roles...")
        roles = pim.get_roles()

        if not roles:
            print("No PIM roles found.")
            return

        # Print role information
        print("\nAvailable PIM Roles:")
        print("-" * 80)
        for role in roles:
            print(role)
            if 'XXX' in role.resource_name:
                try:
                    pim.activate_role(role)
                except PIMError as e:
                    print(f"Error: {str(e)}")
            print("-" * 80)
    except NotAuthenticatedError:
        print("Error: Not authenticated with Azure. Please run 'az login' first.")


if __name__ == "__main__":
    main()
