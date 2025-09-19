def rename_file(original_file, new_file):
    contents = read_file(original_file)
    delete_file(original_file, log_action=False)
    create_file(new_file, contents, log_action=False)
    log(f"Renamed file {original_file} to {new_file}", process="System")