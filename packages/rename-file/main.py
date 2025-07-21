contents = read_file(original_file)
delete_file(original_file, log_action=False)
create_file(new_file, contents, log_action=False)
if log_action:
    log(f"Renamed file {original_file} to {new_file}", process="System")