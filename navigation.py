#!/usr/bin/env python3

from os.path import isdir
from rich.console import Console, JustifyMethod
from rich.layout import Layout
from rich.panel import Panel
from rich.prompt import Prompt
import os, time
from datetime import datetime
import shutil

def get_terminal_size():
    """Retrieve the current terminal dimensions."""
    terminal_size = shutil.get_terminal_size((80, 20))  # Default to 80x20 if detection fails
    return terminal_size.lines

def generate_layout():
    """Create a layout with two columns for directories and files, and a row at the bottom for the command prompt."""
    layout = Layout()
    layout.split(
        Layout(name="input", ratio=1),
        Layout(name="main", ratio=3)
    )
    layout["main"].split_row(
        Layout(name="directories"),
        Layout(name="files")
    )
    layout["input"].split_column(
        Layout(name="left_padding", ratio=2),  # Adding padding
        Layout(name="message", ratio=2),
    )
    return layout

def update_panels(layout, path, files, dirs, dir_page=0, file_page=0, page_size=20):
    """Update the panels with the current directory and file list, implementing pagination."""
    page_size = get_terminal_size() - 9
    dir_start = dir_page * page_size
    file_start = file_page * page_size

    dir_entries = dirs[dir_start:dir_start + page_size]
    file_entries = files[file_start:file_start + page_size]

    dir_panel = Panel("\n".join([f"[bold purple]{dir_start + i}.[/bold purple] [green]{dir}[/green]" for i, dir in enumerate(dir_entries)]), title="Directories", border_style='green')
    file_panel = Panel("\n".join([f"[bold purple]{file_start + i}.[/bold purple] [green]{file}[/green]" for i, file in enumerate(file_entries)]), title="Files", border_style='green')
    layout["main"]["directories"].update(dir_panel)
    layout["main"]["files"].update(file_panel)
    now = datetime.now()
    formatted_date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    layout['input']['message'].update(Panel(f'[bold green]{formatted_date_time}[/bold green]  [bold blue]Welcome to PyPass. Navigate to your csv, json, or yaml file for uploading into Password Manager[/bold blue]', border_style='blue'))
    layout['input']['left_padding'].update(Panel(f'[bold cyan]{formatted_date_time}[/bold cyan]', border_style='blue'))


def file_system_nav()-> str:
    console = Console()
    layout = generate_layout()

    current_path = os.getcwd()
    files = [file for file in os.listdir(current_path) if os.path.isfile(os.path.join(current_path, file))]
    dirs = [dir for dir in os.listdir(current_path) if isdir(os.path.join(current_path, dir))]
    dir_page, file_page = 0, 0
    page_size = 20
    page_size = get_terminal_size() - 9

    update_panels(layout, current_path, files, dirs, dir_page, file_page, page_size)

    while True:
        console.print(layout)
        msg: str = (
                "    Enter command or select file/directory:\n"
                "    < > File Paging, << >> Directory Paging.\n"
                "    cd $HOME, or cd 1 will navigate to home or index.\n"
                "    Index Number and Enter will select a file\n"
                "    q to quit                                              "
                )
        console.print(f'{msg}: ', end="")
        command = input()
        #command = Prompt.ask(msg, console=console)

        if command.startswith("cd"):
            # Change directory
            parts = command.split()
            if len(parts) == 2:
                try:
                    dir_num = int(parts[1])
                    if dir_num < len(dirs):
                        new_path = os.path.join(current_path, dirs[dir_num])
                        if isdir(new_path):
                            current_path = new_path
                            files = [file for file in os.listdir(current_path) if os.path.isfile(os.path.join(current_path, file))]
                            dirs = [dir for dir in os.listdir(current_path) if isdir(os.path.join(current_path, dir))]
                            dir_page, file_page = 0, 0
                            update_panels(layout, current_path, files, dirs, dir_page, file_page)
                    continue
                except ValueError:
                    # Assume it's a path entered
                    new_path = os.path.expandvars(os.path.expanduser(parts[1]))
                    if isdir(new_path):
                        current_path = new_path
                        files = [file for file in os.listdir(current_path) if os.path.isfile(os.path.join(current_path, file))]
                        dirs = [dir for dir in os.listdir(current_path) if isdir(os.path.join(current_path, dir))]
                        dir_page, file_page = 0, 0
                        update_panels(layout, current_path, files, dirs, dir_page, file_page)
                    else:
                        console.print(f"[red]Error: {new_path} is not a directory[/]", justify="center")
                        time.sleep(3)
        elif command.isdigit():
            # Select file by index
            index = int(command)
            if index < len(files):
                console.print(f"[green]File selected: {current_path}/{files[index]}[/]", justify="center")
                return f'{current_path}/{files[index]}'
            else:
                console.print("[red]Error: Invalid file index[/]", justify="center")
        elif command == '>>':  # Next page for directories
            if (dir_page + 1) * page_size < len(dirs):
                dir_page += 1
                update_panels(layout, current_path, files, dirs, dir_page, file_page, page_size)
        elif command == '<<':  # Previous page for directories
            if dir_page > 0:
                dir_page -= 1
                update_panels(layout, current_path, files, dirs, dir_page, file_page, page_size)
        elif command == '>':  # Next page for files
            if (file_page + 1) * page_size < len(files):
                file_page += 1
                update_panels(layout, current_path, files, dirs, dir_page, file_page, page_size)
        elif command == '<':  # Previous page for files
            if file_page > 0:
                file_page -= 1
                update_panels(layout, current_path, files, dirs, dir_page, file_page, page_size)
        elif command == 'q':  # quit
            return ''
        else:
            console.print("[red]Invalid command[/]", justify="center")

if __name__ == "__main__":
    file_system_nav()

