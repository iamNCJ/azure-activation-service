import click
from tabulate import tabulate
from .pim_client import PIMClient, NotAuthenticatedError, PIMError
from .config import CONFIG_DIR, ROLES_CACHE_FILE
import json


@click.group()
def cli():
    """Azure Role Activation Service CLI"""
    pass


@cli.command()
@click.argument('role-id')
@click.option('--justification', '-j', default="CLI activation request", help='Justification for role activation')
def activate(role_id: str, justification: str):
    """Activate an Azure role by its ID"""
    try:
        pim = PIMClient()
        roles = pim.get_roles()
        
        # Find role by ID
        role = next((r for r in roles if r.name == role_id), None)
        if not role:
            click.echo(f"Error: Role with ID {role_id} not found.", err=True)
            return
        
        if role.assignment_type:
            click.echo(f"Role '{role.display_name}' is already activated.", err=True)
            return
            
        result = pim.activate_role(role, justification)
        click.echo(f"Successfully activated role: {role.display_name} - {role.resource_name}")

        # update the cache
        roles = pim.get_roles()
        with open(ROLES_CACHE_FILE, 'w') as f:
            json.dump(pim.serialize_roles(roles), f, indent=4)
        
    except NotAuthenticatedError:
        click.echo("Error: Not authenticated with Azure. Please run 'az login' first.", err=True)
    except PIMError as e:
        click.echo(f"Error: {str(e)}", err=True)


@cli.command()
@click.argument('role-id')
@click.option('--justification', '-j', default="CLI deactivation request", help='Justification for role deactivation')
def deactivate(role_id: str, justification: str):
    """Deactivate an Azure role by its ID"""
    try:
        pim = PIMClient()
        roles = pim.get_roles()
        
        # Find role by ID
        role = next((r for r in roles if r.name == role_id), None)
        if not role:
            click.echo(f"Error: Role with ID {role_id} not found.", err=True)
            return
            
        if not role.assignment_type:
            click.echo(f"Role '{role.display_name}' is not currently activated.", err=True)
            return
            
        result = pim.deactivate_role(role, justification)
        click.echo(f"Successfully deactivated role: {role.display_name}")
        
        # update the cache
        roles = pim.get_roles()
        with open(ROLES_CACHE_FILE, 'w') as f:
            json.dump(pim.serialize_roles(roles), f, indent=4)

    except NotAuthenticatedError:
        click.echo("Error: Not authenticated with Azure. Please run 'az login' first.", err=True)
    except PIMError as e:
        click.echo(f"Error: {str(e)}", err=True)


@cli.command(name='list-roles')
@click.option('--verbose', '-v', is_flag=True, help='Show additional role details')
@click.option('--update', '-u', is_flag=True, help='Force update of cached roles')
def list_roles(verbose: bool, update: bool):
    """List all available Azure PIM roles"""
    try:
        pim = PIMClient()
        roles = None
        
        # Check if we should use cache
        if not update and ROLES_CACHE_FILE.exists():
            try:
                with open(ROLES_CACHE_FILE, 'r') as f:
                    cache_data = json.load(f)
                    # Convert cached data back to Role objects
                    roles = pim.deserialize_roles(cache_data)
            except (json.JSONDecodeError, KeyError):
                roles = None
        
        # Fetch fresh data if needed
        if roles is None or update:
            roles = pim.get_roles()
            # Cache the roles
            with open(ROLES_CACHE_FILE, 'w') as f:
                json.dump(pim.serialize_roles(roles), f, indent=4)

        if not roles:
            click.echo("No PIM roles found.")
            return

        # Prepare table data
        table_data = []
        if verbose:
            headers = ["Role Name", "Resource", "Type", "Status", "Expiry", "Role ID"]
            for role in roles:
                status = "ACTIVATED" if role.assignment_type else "NOT ACTIVATED"
                expiry = role.end_date_time.strftime('%Y-%m-%d %H:%M UTC') if role.end_date_time else "N/A"
                
                table_data.append([
                    role.display_name,
                    role.resource_name,
                    role.resource_type,
                    status,
                    expiry,
                    role.name
                ])
        else:
            headers = ["Role Name", "Resource", "Status", "Expiry"]
            for role in roles:
                status = "ACTIVATED" if role.assignment_type else "NOT ACTIVATED"
                expiry = role.end_date_time.strftime('%Y-%m-%d %H:%M UTC') if role.end_date_time else "N/A"
                
                table_data.append([
                    role.display_name,
                    role.resource_name,
                    status,
                    expiry
                ])

        # Print table
        click.echo(tabulate(table_data, headers=headers, tablefmt="grid"))

    except NotAuthenticatedError:
        click.echo("Error: Not authenticated with Azure. Please run 'az login' first.", err=True)
    except PIMError as e:
        click.echo(f"Error: {str(e)}", err=True)


def main():
    cli()


if __name__ == '__main__':
    main()
