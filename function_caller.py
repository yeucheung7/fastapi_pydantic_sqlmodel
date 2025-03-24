import os
import sys
import importlib.util

## Function registry
class FunctionModel:
    label: str
    func: callable
    description: str

    def __init__(self, script_path: str):
        ## Import from the script
        script_file = os.path.basename(script_path)
        script_name = script_file[:-3]
        spec = importlib.util.spec_from_file_location(script_name, script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        ## Assigning parameters
        self.label = script_name
        self.func = module.command
        self.description = module.description

    def __repr__(self):
        return f"<Function - {self.label}: {self.description}>"
    
    def to_list_row(self) -> str:
        return f"{self.label}\t\t{self.description}"

def main():
    ## Run settings ##
    if len(sys.argv) < 2:
        print("Error: Please provide the intended function as the first ")
        exit(1)
    function_name = sys.argv[1]
    cli_root = "cli"
    this_script = os.path.basename(__file__)
    ##################

    ## Functions registration
    py_paths = [os.path.join(cli_root, fn) for fn in os.listdir(cli_root) if fn.endswith(".py")]
    function_list: list = [FunctionModel(script_path = py_path) for py_path in py_paths]

    ## Help function
    if function_name == "help":
        print(f"Call 'python {this_script} <function label>' to invoke the desired function.")
        print(f"For example, 'python {this_script} help' to print out this help message.\n")

        print("Label\t\t\t\tDescription\n")
        for function in function_list:
            print(function.to_list_row())

        print("\nOr, enter 'help' to print this table")
        exit(0)

    ## Handling function request, without unknown function
    selected_function: FunctionModel = None
    for fn in function_list:
        if fn.label == function_name:
            selected_function = fn
            break

    if selected_function is None:
        print(f"Entered function name {function_name} is not on registered on the list of function.")
        exit(1)

    ## Handling function request
    selected_function.func()

    ## Han""dle function not ending properly
    print("Alert: The function might have ended improperly")
    exit(1)

if __name__ == "__main__":
    main()