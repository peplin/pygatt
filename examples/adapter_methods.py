import click

from bluetooth_adapter import BluetoothAdapter
from bluetooth_adapter.backends import BackendEnum


def main():
    """
    Basic example of how to use the BluetoothAdapter methods. This example
    uses the BGAPIBackend.
    """
    click.secho("Creating BluetoothAdapter", fg='green')
    adapter = BluetoothAdapter(BackendEnum.bgapi)

    click.secho("Enabling adapter", fg='green')
    adapter.enable()

    click.secho("Scanning", fg='green')
    devices = adapter.scan(scan_time_seconds=3)
    for d in devices:
        click.secho(str(d), fg='yellow')

    bonds = list_bonds(adapter)

    click.secho("Deleting the first bond (if there is one)", fg='green')
    if len(bonds) > 0:
        adapter.clear_bond(bonds[0])

    bonds = list_bonds(adapter)

    click.secho("Deleting the rest of the bonds (if there are any)", fg='green')
    if len(bonds) > 0:
        adapter.clear_all_bonds()

    bonds = list_bonds(adapter)

    # TODO: reset example

    click.secho("Disabling adapter", fg='green')
    adapter.disable()


def list_bonds(adapter):
    click.secho("Listing bonds stored on adapter", fg='green')
    bonds = adapter.list_bonds()
    for b in bonds:
        click.secho(hex(b), fg='yellow')
    return bonds


if __name__ == '__main__':
    main()
