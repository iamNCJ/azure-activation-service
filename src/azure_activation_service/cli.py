import click
from tabulate import tabulate
from .pim_client import PIMClient, NotAuthenticatedError, PIMError


@click.group()
def cli():
    """Azure Role Activation Service CLI"""
    pass


@cli.command()
@click.option('--role-name', '-r', required=True, help='Name of the role to activate')
@click.option('--scope', '-s', required=True, help='Scope of the role activation')
def activate(role_name: str, scope: str):
    """Activate an Azure role"""
    pass


@cli.command(name='list-roles')
@click.option('--verbose', '-v', is_flag=True, help='Show additional role details')
def list_roles(verbose: bool):
    """List all available Azure PIM roles"""
    try:
        pim = PIMClient()
        roles = pim.get_roles()

        if not roles:
            click.echo("No PIM roles found.")
            return

        # Prepare table data
        table_data = []
        if verbose:
            headers = ["Role Name", "Resource", "Type", "Status", "Expiry", "Role Definition ID", "Principal ID"]
            for role in roles:
                status = "ACTIVATED" if role.assignment_type else "NOT ACTIVATED"
                expiry = role.end_date_time.strftime('%Y-%m-%d %H:%M UTC') if role.end_date_time else "N/A"
                
                table_data.append([
                    role.display_name,
                    role.resource_name,
                    role.resource_type,
                    status,
                    expiry,
                    role.role_definition_id,
                    role.principal_id
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
