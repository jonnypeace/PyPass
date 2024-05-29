#!/usr/bin/env python3

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Input, Button, Static
from textual.reactive import Reactive
from rich.console import Console

console = Console()

class InputApp(App):
    def compose(self) -> ComposeResult:
        # Create an input widget and a button
        self.input = Input(placeholder="Type something here...")
        self.button = Button(label="Submit", name="submit")
        # Add widgets to the app
        yield Container(self.input, self.button)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        # Handle button press
        if event.button.name == "submit":
            user_input = self.input.value
            console.print(f'You entered: {user_input}', style="bold green")
            exit(0)

if __name__ == "__main__":
    app = InputApp()
    app.run()

