import urwid

class FileExplorer:
    def __init__(self, start_path="system"):
        self.current_path = start_path
        self.file_list = []
        self.selected_files = set()
        self.main_loop = None
        self.update_file_list()

        self.header = urwid.Text(f"📁 {self.current_path}")
        self.footer = urwid.Text("↑↓ navigate | Enter open | space select | r rename | d delete | c copy | e edit | ESC/q quit")
        self.status = urwid.Text("")
        self.body = urwid.ListBox(urwid.SimpleFocusListWalker(self.build_file_widgets()))
        self.layout = urwid.Frame(
            header=self.header,
            body=self.body,
            footer=urwid.Pile([self.footer, self.status])
        )

    def update_file_list(self):
        self.file_list = list_directory_contents(self.current_path)

    def build_file_widgets(self):
        widgets = []
        for name in self.file_list:
            display = f"📄 {name}"
            if name in self.selected_files:
                display = f"* {display}"
            widgets.append(urwid.Text(display))
        return widgets

    def open_selected(self):
        selected_name = self.file_list[self.body.focus_position]
        new_path = f"{self.current_path}/{selected_name}"
        contents = list_directory_contents(new_path)
        if contents and isinstance(contents, list):
            self.current_path = new_path
            self.selected_files.clear()
            self.update_file_list()
            self.header.set_text(f"📁 {self.current_path}")
            self.body.body = urwid.SimpleFocusListWalker(self.build_file_widgets())
        else:
            file_contents = read_file(new_path)
            preview = "\n".join(file_contents[:20]) if file_contents else "(empty or unreadable)"
            preview_box = urwid.Text(preview)

            def return_to_main(btn):
                self.main_loop.widget = self.layout

            back_button = urwid.Button("← Back", on_press=return_to_main)
            self.main_loop.widget = urwid.Frame(
                header=urwid.Text(f"📄 {selected_name}"),
                body=urwid.Filler(preview_box),
                footer=back_button
            )

    def prompt_user(self, prompt_text, callback):
        edit = urwid.Edit(f"{prompt_text}: ")

        def confirm(btn):
            callback(edit.edit_text)

        def cancel(btn):
            self.main_loop.widget = self.layout

        done = urwid.Button("OK", on_press=confirm)
        cancel_btn = urwid.Button("Cancel", on_press=cancel)
        pile = urwid.Pile([edit, urwid.Columns([done, cancel_btn])])
        self.main_loop.widget = urwid.Filler(pile)

    def rename_file(self, new_name):
        name = self.file_list[self.body.focus_position]
        old_path = f"{self.current_path}/{name}"
        new_path = f"{self.current_path}/{new_name}"
        contents = read_file(old_path)
        if contents is not None:
            create_file(new_path, contents)
            delete_file(old_path)
            self.status.set_text(f"Renamed '{name}' to '{new_name}'")
        else:
            self.status.set_text(f"Rename failed: could not read '{name}'")
        self.update_file_list()
        self.body.body = urwid.SimpleFocusListWalker(self.build_file_widgets())
        self.main_loop.widget = self.layout

    def delete_file(self):
        targets = self.selected_files or [self.file_list[self.body.focus_position]]
        deleted = 0
        for name in targets:
            path = f"{self.current_path}/{name}"
            if delete_file(path):
                deleted += 1
        self.status.set_text(f"Deleted {deleted} file(s)")
        self.selected_files.clear()
        self.update_file_list()
        self.body.body = urwid.SimpleFocusListWalker(self.build_file_widgets())

    def copy_file(self, dest_folder):
        targets = self.selected_files or [self.file_list[self.body.focus_position]]
        copied = 0
        for name in targets:
            src_path = f"{self.current_path}/{name}"
            dest_path = f"{dest_folder}/{name}"
            contents = read_file(src_path)
            if contents is not None:
                create_file(dest_path, contents)
                copied += 1
        self.status.set_text(f"Copied {copied} file(s) to '{dest_folder}'")
        self.selected_files.clear()
        self.main_loop.widget = self.layout

    def edit_file(self, name):
        path = f"{self.current_path}/{name}"
        contents = read_file(path)
        if contents is None:
            self.status.set_text(f"Error opening file: '{name}'")
            return

        editor = urwid.Edit(multiline=True)
        editor.set_edit_text("\n".join(contents))

        def save_edit(btn):
            new_contents = editor.edit_text.splitlines()
            create_file(path, new_contents)
            self.status.set_text(f"Saved '{name}'")
            self.main_loop.widget = self.layout

        def cancel_edit(btn):
            self.main_loop.widget = self.layout

        save_btn = urwid.Button("Save", on_press=save_edit)
        cancel_btn = urwid.Button("Cancel", on_press=cancel_edit)
        pile = urwid.Pile([editor, urwid.Columns([save_btn, cancel_btn])])
        self.main_loop.widget = urwid.Filler(pile)

    def handle_input(self, key):
        if key in ("q", "Q", "esc"):
            raise urwid.ExitMainLoop()
        elif key in ("enter", "right"):
            self.open_selected()
        elif key in ("backspace", "left"):
            if "/" in self.current_path:
                self.current_path = "/".join(self.current_path.split("/")[:-1])
                self.selected_files.clear()
                self.update_file_list()
                self.header.set_text(f"📁 {self.current_path}")
                self.body.body = urwid.SimpleFocusListWalker(self.build_file_widgets())
        elif key == " ":
            name = self.file_list[self.body.focus_position]
            if name in self.selected_files:
                self.selected_files.remove(name)
            else:
                self.selected_files.add(name)
            self.body.body = urwid.SimpleFocusListWalker(self.build_file_widgets())
        elif key == "r":
            self.prompt_user("Rename to", self.rename_file)
        elif key == "d":
            self.delete_file()
        elif key == "c":
            self.prompt_user("Copy to folder", self.copy_file)
        elif key == "e":
            name = self.file_list[self.body.focus_position]
            self.edit_file(name)

    def run(self):
        self.main_loop = urwid.MainLoop(self.layout, unhandled_input=self.handle_input)
        self.main_loop.run()

if __name__ == "__main__":
    FileExplorer().run()