import click
from tabulate import tabulate
from .pim_client import PIMClient, NotAuthenticatedError, PIMError
from .config import CONFIG_DIR, ROLES_CACHE_FILE, DEFAULT_IMPORT_CONFIG_FILE, AUTO_ACTIVATE_CONFIG
import json


@click.group()
def cli():
    """Azure Role Activation Service CLI"""
    pass


def load_roles_from_cache(pim: PIMClient) -> list | None:
    """Load roles from cache file if available"""
    if ROLES_CACHE_FILE.exists():
        try:
            with open(ROLES_CACHE_FILE, 'r') as f:
                cache_data = json.load(f)
                return pim.deserialize_roles(cache_data)
        except (json.JSONDecodeError, KeyError):
            return None
    return None


def refresh_and_save_cache(pim: PIMClient) -> list:
    """Fetch fresh roles and update cache"""
    roles = pim.get_roles()
    with open(ROLES_CACHE_FILE, 'w') as f:
        json.dump(pim.serialize_roles(roles), f, indent=4)
    return roles


@cli.command()
@click.argument('role-id')
@click.option('--justification', '-j', default="CLI activation request", help='Justification for role activation')
def activate(role_id: str, justification: str):
    """Activate an Azure role by its ID"""
    try:
        pim = PIMClient()
        # Try to load from cache first
        roles = load_roles_from_cache(pim) or refresh_and_save_cache(pim)
        
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

        # Refresh cache after activation
        refresh_and_save_cache(pim)
        
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
        # Try to load from cache first
        roles = load_roles_from_cache(pim) or refresh_and_save_cache(pim)
        
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
        
        # Refresh cache after deactivation
        refresh_and_save_cache(pim)

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
        
        # Load roles based on update flag and cache availability
        roles = None if update else load_roles_from_cache(pim)
        if roles is None:
            roles = refresh_and_save_cache(pim)

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


@cli.command(name='import-config')
@click.argument('config_file', type=click.Path(exists=True), required=False, default=DEFAULT_IMPORT_CONFIG_FILE)
def import_config(config_file):
    """Import role configuration from JSON file. If no file is specified, uses the default config file."""
    try:
        with open(config_file, 'r') as f:
            config_data = json.load(f)

        # Convert old format to new format if needed
        if "autoActivationEnabled" in config_data:
            old_config = config_data["autoActivationEnabled"]
            pim = PIMClient()
            roles = load_roles_from_cache(pim) or refresh_and_save_cache(pim)
            
            new_config = {"roles": []}
            for role in roles:
                auto_activate = old_config.get(role.name, False)
                new_config["roles"].append({
                    "id": role.name,
                    "name": role.display_name,
                    "resource": role.resource_name,
                    "autoActivate": auto_activate
                })
            config_data = new_config

        # Validate config structure
        if "roles" not in config_data:
            raise click.ClickException("Invalid config file format. Must contain 'roles' list.")

        # Save the config
        with open(AUTO_ACTIVATE_CONFIG, 'w') as f:
            json.dump(config_data, f, indent=4)
        
        click.echo(f"Successfully imported configuration for {len(config_data['roles'])} roles")
        
        # Display the imported configuration
        table_data = [
            [r["name"], r["resource"], "Yes" if r["autoActivate"] else "No"]
            for r in config_data["roles"]
        ]
        headers = ["Role Name", "Resource", "Auto-Activate"]
        click.echo("\nImported Configuration:")
        click.echo(tabulate(table_data, headers=headers, tablefmt="grid"))

    except json.JSONDecodeError:
        click.echo("Error: Invalid JSON file", err=True)
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)


def main():
    cli()


if __name__ == '__main__':
    main()
