from datetime import date
import json
import logging
import os
import pyfiglet
import requests
from rich.logging import RichHandler
from rich.console import Console
from rich.progress import Progress
import typer
from zipfile import ZipFile
from git import Repo, RemoteProgress
import urllib.parse

ROOT_FOLDER = "C:\\SHARED\\AzureDevOps"

API_VERSION = "api-version=7.2-preview" #7.2-preview.1 gave issues with some endpoints
#CLI_API_VERSION = "api-version=5.0-preview.2"


border = "=" * 50

def load_config():
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("Error: Config file is not a valid JSON.")
        return {}

class LoggerBase:
    def __init__(self, log_ne, file_ne, debug=False):
        # Ensure each logger is uniquely ned to avoid conflicts.
        self.logger = logging.getLogger(log_ne)
        self.configure_logger(file_ne, debug)

    def configure_logger(self, file_ne, debug):
        self.logger.handlers = []  # Clear existing handlers to prevent duplicate messages
        file_handler = logging.FileHandler(os.path.join(ROOT_FOLDER,f"{file_ne}"), "a")
        if file_ne == "zeus-token.log":
            formatter = logging.Formatter("")
        else:
            formatter = logging.Formatter("%(asctime)s,%(levelne)s,%(message)s", "%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        # Prevent logging from propagating to the root logger
        self.logger.propagate = False

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warn(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)

console = Console()

class AzureDevopsClient():
    def __init__(self, token, organization, project=None, debug=False):
        config = load_config()
        self.token = token if token is not None else config.get("token")
        self.organization = organization if organization is not None else config.get("organization")
        self.project = project if project is not None else config.get('project', False)
        self.base_url = f"https://dev.azure.com/{self.organization}"
        self.headers = {
            "Accept": "application/json; " + API_VERSION,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        }
        self.auth = ("", self.token)
        self.session = requests.Session()
        self.verify = True
        self.user_info = None
        self.debug = debug if debug is not None else config.get('debug', False)
        self.logger = LoggerBase("main_logger", f"zeus-auth-{date.today().isoformat()}.log", debug=self.debug).logger
        self.token_logger = LoggerBase("token_logger", "zeus-token.log", debug=self.debug).logger
        
        # cmd_args = self.parse_command(os.sys.argv[1:])
        # self.logger.info(f"CMD: ({cmd_args})")

    def __make_api_request(self, endpoint, content=None, params=None) -> requests.Response:
        url = f"{self.base_url}/{endpoint}"

        if content is not None:
            response = self.session.post(url, json=content, params=params, headers=self.headers, auth=self.auth, verify=self.verify)
        else:
            response = self.session.get(url, params=params, headers=self.headers, auth=self.auth, verify=self.verify)
        #response.raise_for_status()
        executing_as = "N/A"
        if response.status_code == 200:
            executing_as = response.headers['X-VSS-UserData'].split(":")[1]
        self.logger.info(f"{response.url},{response.status_code},{executing_as}")
        #self.token_logger.info(f"Token: {self.token} --> {executing_as}")
        with open(os.path.join(ROOT_FOLDER, 'zeus-token.log'), 'r') as file:
            if f"{self.token}" in file.read():
                pass
            else:
                self.token_logger.info(f"Token: {self.token} --> {executing_as}")
        #print(response.url)
        return response
    
    def parse_command(self, commandArgs) -> None:
        script_args = commandArgs
        
        parsed_command = "zeus.py "
        parsed_command += " ".join(script_args)
        # for i in range(len(script_args)):
        #     if script_args[i] == "--token":
        #         script_args[i+1] = f"{self.token}"
        #         #script_args[i+1] = "<redacted>"
        #     else:
        #         continue
        # parsed_command += " | CLEAN: zeus.py "
        # parsed_command += " ".join(script_args)
        #self.logger.info(f'NEW FUNCTION Script executed with arguments: zeus.py {parsed_command}')
        return parsed_command

 ############################## ENUM / ORG ##############################   
    def get_user_info(self) -> dict:
        logging.debug("Getting User Information")
        response = self.__make_api_request("_apis/ConnectionData")
        if response and response.status_code == 200:
            if self.user_info is None:
                self.user_info = response.json()
            return self.user_info
        elif response.status_code == 203:
            console.print(f"[red]Unauthorized: The provided token format is invalid.[/red]")
            raise typer.Exit()
        elif response.status_code == 401:
            console.print(f"[red]Unauthorized: The provided token is no longer valid.[/red]")
            raise typer.Exit()
        else:
            console.print(f"[red]Request failed with status code: {response.status_code}[/red]")
            raise typer.Exit()
    
    def get_user_id(self) -> str:
        logging.debug("Getting User ID")
        if self.user_info is None:
            self.get_user_info()
        return self.user_info["authenticatedUser"]["id"]
    
    def token_info(self) -> dict:
        logging.debug("Getting token info")
        user_info = self.get_user_info()
        displayne = user_info["authenticatedUser"]["providerDisplayne"]
        account = user_info["authenticatedUser"]["properties"]["Account"]["$value"]
        id = user_info["authenticatedUser"]["id"]
        return {"displayne": displayne, "account": account, "id": id}

    def get_token_scopes(self, show_output=False) -> dict:
        
        projects = self.get_projects()
        self.project = projects[0]['ne']

        
        scopes = {
            "vso.agentpools": {
                "description": "Management of Azure Pipelines Agent Pools, including pool creation, deletion, and updating agent details.",
                "endpoint": "_apis/distributedtask/pools",
                "url": f"https://dev.azure.com/{self.organization}",
                "Access": False
            },
            "vso.build": {
                "description": "Access and management of build pipelines, including creating builds, retrieving build results, and managing build definitions.",
                "endpoint": "_apis/build/builds",
                "url": f"https://dev.azure.com/{self.organization}/{self.project}",
                "Access": False
            },
            "vso.code": {
                "description": "Operations related to source code management, including accessing repositories, commits, pull requests, and branching.",
                "endpoint": "_apis/git/repositories",
                "url": f"https://dev.azure.com/{self.organization}/{self.project}",
                "Access": False
            },
            "vso.entitlements": {
                "description": "Management of user entitlements, covering access levels, extensions, and service access permissions within Azure DevOps.",
                "endpoint": "_apis/userentitlements",
                "url": f"https://vsaex.dev.azure.com/{self.organization}",
                "Access": False
            },
            "vso.graph": {
                "description": "Access to Azure DevOps Graph APIs for querying user and group information within the organization.",
                "endpoint": "_apis/graph/users",
                "url": f"https://vssps.dev.azure.com/{self.organization}",
                "Access": False
            },
            # "vso.project": {
            #     "description": "Access to project-level information and operations, including project creation, deletion, and retrieving project details.",
            #     "endpoint": "_apis/projects",
            #     "url": f"https://dev.azure.com/{self.organization}",
            #     "Access": False
            # },
            "vso.securefiles_read": {
                "description": "Read-only access to secure files stored in Azure Pipelines, such as certificates, passwords, and other sensitive data.",
                "endpoint": "_apis/distributedtask/securefiles",
                "url": f"https://dev.azure.com/{self.organization}/{self.project}",
                "Access": False
            },
            "vso.serviceendpoint": {
                "description": "Access to service endpoints, enabling interactions with external services and systems integrated with Azure DevOps.",
                "endpoint": "_apis/serviceendpoint/endpoints",
                "url": f"https://dev.azure.com/{self.organization}/{self.project}",
                "Access": False
            },
            "vso.taskgroups": {
                "description": "Operations related to Azure Pipelines Task Groups, including creating, updating, and managing task groups.",
                "endpoint": "_apis/distributedtask/taskgroups",
                "url": f"https://dev.azure.com/{self.organization}/{self.project}",
                "Access": False
            },
            "vso.variablegroups_read": {
                "description": "Read-only access to variable groups used in Azure Pipelines, for managing variables across multiple pipelines and environments.",
                "endpoint": "_apis/distributedtask/variablegroups",
                "url": f"https://dev.azure.com/{self.organization}/{self.project}",
                "Access": False
            },
        }


        for scope, info in scopes.items():
            self.base_url = info["url"]
            try:
                response = self.__make_api_request(info["endpoint"])
                if response.status_code == 200:
                    scopes[scope]["Access"] = True
                else:
                    scopes[scope]["Access"] = False
            except Exception as e:
                self.logger.error(f"Error checking scope '{scope}': {str(e)}")
            
            if show_output:
                if scopes[scope]["Access"]:
                    console.print(border)
                    console.print(f"[green][+] Scope: {scope}[/green]")
                    console.print(f"[green][+] Access: Granted[/green]")
                    console.print(f"[green][+] Description: {info['description']}[/green]")
                    console.print(border)
                else:
                    console.print(border)
                    console.print(f"[red][-] Scope: {scope}[/red]")
                    console.print(f"[red][-] Access: Denied[/red]")
                    console.print(f"[red][-] Description: {info['description']}[/red]")
                    console.print(border)

        return scopes

    def get_user_pats(self, show_output=False) -> dict:
        logging.debug("Getting user PATs")
        self.base_url = f"https://vssps.dev.azure.com/{self.organization}"
        response = self.__make_api_request("_apis/Token/SessionTokens")
        pats = []

        if response and response.status_code == 200:
            response = response.json()
            #console.print(response)
            for pat in response.get("value", []):
                pats.append({"displayne": pat["displayne"], "id": pat["authorizationId"], "scope": pat["scope"]})

                if show_output:
                    console.print(border)
                    console.print("[green][+] PAT ne: {}[/green]".format(pat["displayne"]))
                    console.print("[green][+] PAT ID: {}[/green]".format(pat["authorizationId"]))
                    console.print("[green][+] PAT Scope: {}[/green]".format(pat["scope"]))
                    console.print("[green][+] PAT Expires: {}[/green]".format(pat["validTo"]))
                    console.print("[green][+] PAT isValid: {}[/green]".format(pat["isValid"]))
                    console.print(border)
        else:
            if show_output:
                console.print(f"[red]Error: {response.status_code}[/red]")
            return

        return pats

    def get_user_ssh_keys(self, show_output=False) -> dict:
        logging.debug("Getting user SSH keys")
        self.base_url = f"https://vssps.dev.azure.com/{self.organization}"
        response = self.__make_api_request("_apis/Token/SessionTokens?isPublic=true&includePublicData=true")
        ssh_keys = []

        if response and response.status_code == 200:
            response = response.json()
            for ssh_key in response.get("value", []):
                ssh_keys.append({"displayne": ssh_key["displayne"], "id": ssh_key["authorizationId"], "scope": ssh_key["scope"]})

                if show_output:
                    console.print(border)
                    console.print("[green][+] SSH Key ne: {}[/green]".format(ssh_key["displayne"]))
                    console.print("[green][+] SSH Key ID: {}[/green]".format(ssh_key["authorizationId"]))
                    console.print("[green][+] SSH Key Scope: {}[/green]".format(ssh_key["scope"]))
                    console.print("[green][+] SSH Key Expires: {}[/green]".format(ssh_key["validTo"]))
                    console.print("[green][+] Public SSH Key: {}[/green]".format(ssh_key["publicData"]))
                    console.print(border)
        else:
            if show_output:
                console.print(f"[red]Error: {response.status_code}[/red]")
            return

        return ssh_keys

    def get_projects(self, show_output=False) -> dict:
        logging.debug("Getting projects")
        response = self.__make_api_request("_apis/projects")
        projects = []

        if response and response.status_code == 200:
            response = response.json()
            for project in response.get("value", []):
                projects.append({"ne": project["ne"], "id": project["id"]})

                if show_output:
                    console.print(border)
                    console.print("[green][+] Project ne: {}[/green]".format(project["ne"]))
                    console.print("[green][+] Project ID: {}[/green]".format(project["id"]))
                    console.print(border)
        elif response.status_code == 401:
            console.print(f"[red]Unauthorized: The provided token is no longer valid.[/red]")
            raise typer.Exit()
        
        return projects

    def get_users(self, show_output=False) -> dict:
        logging.debug("Getting users")
        users = []

        self.base_url = f"https://vssps.dev.azure.com/{self.organization}"
        response = self.__make_api_request("_apis/graph/users")
        if response and response.status_code == 200:
            response = response.json()
            for user in response.get("value", []):
                if "@" not in user["principalne"]:
                    continue

                user_info = {"ne": user["displayne"], "email": user["principalne"]}
                users.append(user_info)
                if show_output:
                    console.print(border)
                    console.print("[green][+] User ne: {}[/green]".format(user["displayne"]))
                    console.print("[green][+] User Email: {}[/green]".format(user["principalne"]))
                    console.print(border)
        else:
            if show_output:
                console.print(f"[red]Error: {response.status_code}[/red]")
            return

        return users
    
    def get_groups(self, show_output=False) -> dict:
        logging.debug("Getting groups")
        groups = []

        self.base_url = f"https://vssps.dev.azure.com/{self.organization}"
        response = self.__make_api_request("_apis/graph/groups")
        if response and response.status_code == 200:
            response = response.json()
            for group in response.get("value", []):
                group_info = {"ne": group["displayne"], "principalne": group["principalne"],"originid": group['originId'], "description": group["description"]}
                groups.append(group_info)
                if show_output:
                    console.print(border)
                    console.print("[green][+] Group ne: {}[/green]".format(group["displayne"]))
                    console.print("[green][+] Group Principal ne: {}[/green]".format(group["principalne"]))
                    console.print("[green][+] Group Origin ID: {}[/green]".format(group["originId"]))
                    console.print("[green][+] Group Description: {}[/green]".format(group["description"]))
                    console.print(border)
        else:
            if show_output:
                console.print(f"[red]Error: {response.status_code}[/red]")
            return

        return groups

    def get_group_members(self, show_output=False) -> dict:
        logging.debug("Getting group members")
        groups = []
        groups = self.get_groups()

        self.base_url = f"https://vsaex.dev.azure.com/{self.organization}"
        group_members = []
        project_group_members = {}

        for group in groups:
            groupPrincipalne = group.get("principalne")
            originId = group.get("originid")
            try:
                response = self.__make_api_request("_apis/GroupEntitlements/" + f"{originId}" + "/members")
                if response and response.status_code == 200:
                    response = response.json()
                    for member in response.get("items", []):
                        userne = member.get("user", {}).get("principalne")
                        displayne = member.get("user", {}).get("displayne")

                        if userne and displayne:
                            group_members.append({"userne": userne, "displayne": displayne})
                    
                    if group_members:
                        project_group_members[groupPrincipalne] = group_members


                else:
                    if show_output:
                        console.print(f"[red]Error: {response.status_code}[/red]")
                    return
            except Exception as e:
                print(e)
                continue


        if show_output:
            for key, value in project_group_members.items():
                console.print(border)
                console.print(f"[bold][+] Group: {key}[/bold]")
                if value:
                    for member in value:
                        console.print(f"[green]{member.get('displayne')} - {member.get('userne')}[/green]")
                else:
                    print("\tNo Members")
                console.print(border)

        return project_group_members

    def get_teams(self, show_output=False) -> dict:
        logging.debug("Getting teams")
        teams = []
        response = self.__make_api_request("_apis/teams")
        if response and response.status_code == 200:
            response = response.json()
            for team in response.get("value", []):
                team_info = {"ne": team["ne"], "id": team["id"], "description": team["description"]}
                teams.append(team_info)
                if show_output:
                    console.print(border)
                    console.print("[green][+] Team ne: {}[/green]".format(team["ne"]))
                    console.print("[green][+] Team ID: {}[/green]".format(team["id"]))
                    console.print("[green][+] Team Description: {}[/green]".format(team["description"]))
                    console.print(border)
        else:
            if show_output:
                console.print(f"[red]Error: {response.status_code}[/red]")
            return

        return teams

    def get_nespace_permissions(self, show_output=False) -> dict:
        logging.debug("Getting nespace permissions")
        nespace_permissions = []
        response = self.__make_api_request("_apis/securitynespaces")
        if response and response.status_code == 200:
            response = response.json()
            for nespace in response.get("value", []):
                securitynespaceId = nespace.get("nespaceId")
                securitynespacene = nespace.get("ne")
                securitynespaceActions = nespace.get("actions", [])

                console.print("[green][+] nespace ne: {}[/green]".format(securitynespacene))
                console.print("[green][+] nespace ID: {}[/green]".format(securitynespaceId))

                #TO BE CONTINUED
                #GET /ABCD-us-SadDadZone-rt/_apis/AccessControlLists/c788c23e-1b46-4162-8f5e-d7585343b5de?token=29ecc4cf-d0b7-4504-a6bd-d05c4235cf94&descriptors=Microsoft.IdentityModel.Claims.ClaimsIdentity%3B513294a0-3e20-41b2-a970-6d30bf1546fa%5Cteddy.palmer%40ABCD.com&includeExtendedInfo=true&recurse=false
                #az devops security permission show --id 'c788c23e-1b46-4162-8f5e-d7585343b5de' --subject 'teddy.palmer@ABCD.com' --token '29ecc4cf-d0b7-4504-a6bd-d05c4235cf94' --debug
                
############################## ENUM / PROJECT ##############################
    def get_repos(self, project=None, download=False, manual=False, all_projects=False, show_output=False) -> dict:
        
        class CloneProgress(RemoteProgress):
            def __init__(self, progress):
                super().__init__()
                self.progress = progress
                self.task_id = self.progress.add_task("Cloning...", total=100)

            def update(self, op_code, cur_count, max_count=None, message=''):
                self.progress.update(self.task_id, advance=cur_count, total=max_count, description=message)

        logging.debug("Getting repos")
        project = project if project is not None else self.project
        repos = []
        
        if not all_projects:
            response = self.__make_api_request(f"{project}/_apis/git/repositories")
            repos = []
            if response and response.status_code == 200:
                response = response.json()
                for repo in response.get("value", []):
                    repos.append({"ne": repo["ne"], "id": repo["id"]})

                    repo_ne = repo["ne"]
                    repo_url = f"https://{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"
                    clone_dir = os.path.join(os.getcwd(), project, "repos", repo_ne)

                    if show_output:
                        console.print(border)
                        console.print("[green][+] Repo ne: {}[/green]".format(repo["ne"]))
                        console.print("[green][+] Repo ID: {}[/green]".format(repo["id"]))
                        #console.print(f"git clone https://{self.organization}:{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}")
                        console.print(border)
                    
                    if download:
                        try:
                            with Progress(console=console) as progress:
                                console.print(border)
                                console.print(f"[bold][green][+] Downloading Repo: {repo_ne}...[/green][/bold]")
                                Repo.clone_from(repo_url, clone_dir, progress=CloneProgress(progress))
                                console.print(f"\n[bold][green][+] Repo Downloaded: {repo_ne}[/green][/bold]")
                                #console.print(border)
                        except Exception as e:
                            console.print(f"[red]Error: {e}[/red]")
                            return
                    if manual:
                        # write to file 
                        #clone_command_old = f"git clone https://{self.organization}:{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"
                        clone_command = f"git clone https://{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"
                        git_command_file = os.path.join(os.getcwd(), project, "repos", "git-clone-commands.txt")

                        if not os.path.exists(os.path.join(os.getcwd(), project, "repos")):
                            os.makedirs(os.path.join(os.getcwd(), project, "repos"))
                        with open(f"{git_command_file}", "a") as file:
                            file.write(f"{clone_command}\n")
                            file.close()
                            if show_output:
                                console.print(border)
                                console.print(f"[bold][green][+] Git Clone Command Saved: {project}/repos/git-clone-commands.txt[/green][/bold]")
                                console.print(border)

        elif all_projects:
            projects = self.get_projects()
            for project in projects:
                project_ne = project["ne"]
                console.print(f"\n[+] Enumerating {project_ne}...\n")
                project_ne = urllib.parse.quote(project_ne)
                response = self.__make_api_request(f"{project_ne}/_apis/git/repositories")
                #print(f"{project_ne}")
                if response and response.status_code == 200:
                    response = response.json()
                    #print(response)
                    for repo in response.get("value", []):
                        repos.append({"ne": repo["ne"], "id": repo["id"]})

                        repo_ne = repo["ne"]
                        repo_url = f"https://{self.token}@dev.azure.com/{self.organization}/{project_ne}/_git/{urllib.parse.quote(repo_ne)}"
                        clone_dir = os.path.join(os.getcwd(), project["ne"], "repos", repo_ne)

                        if show_output:
                            console.print(border)
                            console.print("[green][+] Repo ne: {}[/green]".format(repo["ne"]))
                            console.print("[green][+] Repo ID: {}[/green]".format(repo["id"]))
                            #console.print(f"git clone https://{self.organization}:{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}")
                            console.print(border)
                        
                        if download:
                            try:
                                with Progress(console=console) as progress:
                                    console.print(border)
                                    console.print(f"[bold][green][+] Downloading Repo: {repo_ne}...[/green][/bold]")
                                    Repo.clone_from(repo_url, clone_dir, progress=CloneProgress(progress))
                                    console.print(f"\n[bold][green][+] Repo Downloaded: {repo_ne}[/green][/bold]")
                                    #console.print(border)
                            except Exception as e:
                                console.print(f"[red]Error: {e}[/red]")
                                return
                        if manual:
                            # write to file 
                            #clone_command_old = f"git clone https://{self.organization}:{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"
                            #clone_command = f"git clone https://{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"

                            clone_command = f"git clone https://{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project_ne)}/_git/{urllib.parse.quote(repo_ne)}"
                            #TO DO: Point this to the ROOT project folder, instead of current directory
                            git_command_file = os.path.join(os.getcwd(), project["ne"], "repos", "git-clone-commands.txt")

                            if not os.path.exists(os.path.join(os.getcwd(), project["ne"], "repos")):
                                os.makedirs(os.path.join(os.getcwd(), project["ne"], "repos"))
                            with open(f"{git_command_file}", "a") as file:
                                file.write(f"{clone_command}\n")
                                file.close()
                                if show_output:
                                    console.print(border)
                                    console.print(f"[bold][green][+] Git Clone Command Saved: {project["ne"]}/repos/git-clone-commands.txt[/green][/bold]")
                                    console.print(border)
        
        return repos

    def get_pipelines(self, project=None, show_output=False) -> dict:
        logging.debug("Getting pipelines")
        project = project if project is not None else self.project
        response = self.__make_api_request(f"{project}/_apis/pipelines")
        pipelines = []

        if response and response.status_code == 200:
            response = response.json()
            for pipeline in response.get("value", []):
                pipelines.append({"ne": pipeline["ne"], "id": pipeline["id"]})

                if show_output:
                    console.print(border)
                    console.print("[green][+] Pipeline ne: {}[/green]".format(pipeline["ne"]))
                    console.print("[green][+] Pipeline Build/Run ID: {}[/green]".format(pipeline["id"]))
                    console.print(border)
        
        return pipelines

    def get_pipeline_runs(self, project=None, show_output=False) -> dict:
        logging.debug("Getting pipeline runs")
        project = project if project is not None else self.project
        pipeline_runs = []
        pipeline_ids = []

        pipelines = self.get_pipelines(project=project)
        for pipeline in pipelines:
            pipeline_ids.append(pipeline["id"])

        for pipeline_id in pipeline_ids:
            response = self.__make_api_request(f"{project}/_apis/pipelines/{pipeline_id}/runs")
            if response and response.status_code == 200:
                response = response.json()
                for pipeline_run in response.get("value", []):
                    pipeline_runs.append({"ne": pipeline_run["ne"], "id": pipeline_run["id"]})

                    if show_output:
                        console.print(border)
                        #print(pipeline_run)
                        console.print(f'[green][+] Pipeline ne: {pipeline_run["pipeline"]["ne"]}[/green]')
                        console.print(f'[green][+] Pipeline Definition ID:{pipeline_run["pipeline"]["id"]}[/green]')
                        console.print("[green][+] Pipeline Run ne: {}[/green]".format(pipeline_run["ne"]))
                        console.print("[green][+] Pipeline Run/Build ID: {}[/green]".format(pipeline_run["id"]))
                        console.print(border)
        
        return pipeline_runs

    def get_builds(self, project=None, show_output=False) -> dict:
        logging.debug("Getting builds")
        project = project if project is not None else self.project
        builds = []
        response = self.__make_api_request(f"{project}/_apis/build/builds")
        if response and response.status_code == 200:
            response = response.json()
            for build in response.get("value", []):
                builds.append({"ne": build["definition"]["ne"], "id": build["id"], "definition_id": build["definition"]["id"]})

                if show_output:
                    console.print(border)
                    console.print("[green][+] Build ne: {}[/green]".format(build["definition"]["ne"]))
                    console.print("[green][+] Build/Run ID: {}[/green]".format(build["id"]))
                    console.print("[green][+] Build Defenition ID: {}[/green]".format(build["definition"]["id"]))
                    console.print(border)
        
        return builds

    def get_defintions(self, project=None, show_output=False) -> dict:
        logging.debug("Getting definitions")
        project = project if project is not None else self.project
        definitions = []
        response = self.__make_api_request(f"{project}/_apis/build/definitions")
        if response and response.status_code == 200:
            response = response.json()
            for definition in response.get("value", []):
                definitions.append({"ne": definition["ne"], "id": definition["id"]})

                if show_output:
                    console.print(border)
                    console.print("[green][+] Definition ne: {}[/green]".format(definition["ne"]))
                    console.print("[green][+] Definition ID: {}[/green]".format(definition["id"]))
                    console.print(border)

    def get_artifact(self, runID, project=None, show_output=False) -> dict:
        logging.debug("Getting artifact")
        project = project if project is not None else self.project
        response = self.__make_api_request(f"{project}/_apis/build/builds/{runID}/artifacts")
        artifacts = []
        if response and response.status_code == 200:
            response = response.json()
            #print(response)
            for artifact in response.get("value", []):
                artifacts.append({"ne": artifact["ne"], "id": artifact["id"], "downloadUrl": artifact["resource"]["downloadUrl"]})
                if show_output:
                    console.print(border)
                    console.print("[green][+] Artifact ne: {}[/green]".format(artifact["ne"]))
                    console.print("[green][+] Artifact ID: {}[/green]".format(artifact["id"]))
                    console.print("[green][+] Build/Run ID: {}[/green]".format(runID))
                    console.print("[green][+] Artifact Download URL: {}[/green]".format(artifact["resource"]["downloadUrl"]))
                    console.print(border)
        elif response.status_code == 404:
            console.print(f"[red][!] No Build Artifacts Found for Run ID: {runID}[/red]")
        return artifacts

    def get_build_artifacts(self, project=None, show_output=False) -> dict:
        logging.debug("Getting build artifacts")
        project = project if project is not None else self.project
        builds = self.get_builds(project=project)
        for build in builds:
            runID = build["id"]
            self.get_artifact(runID=runID, project=project, show_output=True)

    #NEED TO FINISH CODE SEARCH
    def code_search(self, project=None, searchText=None, show_output=False) -> dict:
        logging.debug("Code search")
        project = project if project is not None else self.project
        self.base_url = f"https://almsearch.dev.azure.com/{self.organization}/{project}"
        payload = {
        "searchText": searchText,
        "skipResults": 0,
        "takeResults": 1000,
        "isInstantSearch": True
        }
        response = self.__make_api_request(f"_apis/search/codesearchresults", content=payload)
        #response = self.__make_api_request(f"_apis/search/codeAdvancedQueryResults", content=payload)
        if response and response.status_code == 200:
            console.print("[green][+] Code Search Results:[/green]")
            console.print(response.url)
            console.print(response.status_code)
            console.print(response.text)
        elif response.status_code == 401:
            console.print(f"[red]Unauthorized: The provided token is no longer valid.[/red]")
            raise typer.Exit()
        elif response.status_code == 404:
            console.print(f"[red][!] The extension ms.vss-code-search is not installed! :( [Need organization owner or a project collection administrator to install extensions][/red]")

        #console.print(response.json())
        # if response and response.status_code == 200:
        #     response = response.json()
        #     for result in response.get("results", []):
        #         if show_output:
        #             console.print(border)
        #             console.print("[green][+] Result: {}[/green]".format(result))
        #             console.print(border)
        # else:
        #     console.print(f"[red]Error: {response.status_code}[/red]")

    def get_project_group_permissions(self, project=None, show_output=False) -> dict:
        logging.debug("Getting group permissions")
        project = project if project is not None else self.project
        #groups = self.get_groups()
        group_permissions = []
        project_group_permissions = {}

        payload = {
        'contributionIds': ['ms.vss-admin-web.org-admin-groups-data-provider'],
        'dataProviderContext': {
            'properties': {
                'sourcePage': {
                    'routeValues': {
                        'project': project,
                        'adminPivot': 'permissions',
                        'controller': 'ContributedPage',
                        'action': 'Execute'
                    }
                }
            }
        }
    }


        response = self.__make_api_request("_apis/Contribution/HierarchyQuery", content=payload)
        if response and response.status_code == 200:
            response = response.json()
            #console.print(response)

            groups = response["dataProviders"]["ms.vss-admin-web.org-admin-groups-data-provider"]["identities"]
            groupCount = response["dataProviders"]["ms.vss-admin-web.org-admin-groups-data-provider"]["totalIdentityCount"]
            
            #console.print(groups)
            # console.print(type(data))

            
            if show_output:
                console.print("[bold][green][+] Total Groups Found: " f"{groupCount}[/bold]")

            for group in groups:
                group_info = {"ne": group["displayne"], "description": group["description"], "principalne": group["principalne"], "descriptor": group["descriptor"]}
                group_permissions.append(group_info)
                if show_output:
                    console.print(border)
                    console.print("[green][+] Group ne: {}[/green]".format(group["displayne"]))
                    console.print("[green][+] Group Description: {}[/green]".format(group["description"]))
                    console.print("[green][+] Group Principal ne: {}[/green]".format(group["principalne"]))
                    #console.print("[green][+] Group Descriptor: {}[/green]".format(group["descriptor"]))
                    #console.print(border)

                    console.print("\n[+] Group Members")
                    self.get_project_group_members(descriptor=group["descriptor"], show_output=True)
                    console.print(border)


        return project_group_permissions
    
    def get_project_group_members(self, descriptor=None, show_output=False) -> dict:
        logging.debug("Getting group members")
        group_members = []

        payload = {
            'contributionIds': ['ms.vss-admin-web.org-admin-group-members-data-provider'],
            'dataProviderContext': {
                'properties': {
                    'subjectDescriptor': descriptor,
                    'sourcePage': {
                        'routeValues': {
                            'adminPivot': 'permissions',
                            'controller': 'ContributedPage',
                            'action': 'Execute'
                        }
                    }
                }
            }
        }

        response = self.__make_api_request("_apis/Contribution/HierarchyQuery", content=payload)
        if response and response.status_code == 200:
            response_data = response.json()
            
            # console.print(response_data)
            # Accessing the dataProviders directly and safely
            data_providers = response_data.get('dataProviders', {})
            group_data_provider = data_providers.get('ms.vss-admin-web.org-admin-group-members-data-provider', {})

            # console.print(group_data_provider)
            
            # # Safely accessing 'identities' if exists
            identities = group_data_provider.get('identities', [])
            
            for identity in identities:

                if identity.get('subjectKind') == 'group':
                    if show_output:
                        #console.print(border)
                        # console.print("[+] Group ne: {}".format(identity.get('displayne')))

                        self.get_project_group_members(descriptor=identity.get('descriptor'), show_output=True)
                    #console.print(identity.get('displayne'))

                if identity.get('subjectKind') == 'user':
                    # console.print(identity)

                    # console.print(identity.get('displayne'))
                    # console.print(identity.get('mailAddress'))
                    member_info = {
                        "ne": identity.get('displayne'),
                        "mailAddress": identity.get("mailAddress", "No mail address provided")
                    }
                    group_members.append(member_info)

                    #check if ne or email already in group members

                    
                    if show_output:
                        console.print("\n[+] User ne: {}".format(identity.get('displayne')))
                        console.print("[+] User Principal ne: {}".format(identity.get('mailAddress')))

        return group_members




############################## EXTRACT / DOWNLOAD ##############################
    def download_artifact(self, runID, project=None, show_output=False, unzip=False) -> None:
        logging.debug("Downloading artifact")
        project = project if project is not None else self.project
        artifact = self.get_artifact(runID=runID, project=project, show_output=False)
        if artifact:
                artifactne = artifact[0]["ne"]
                downloadUrl = artifact[0]["downloadUrl"]
                downloadUrl = downloadUrl.replace(f"https://dev.azure.com/{self.organization}/", "")
                response = self.__make_api_request(downloadUrl)
                if response and response.status_code == 200:
                    if not os.path.exists(os.path.join(ROOT_FOLDER, self.organization, f"{project}", "build-artifacts", f"{runID}")):
                        os.makedirs(os.path.join(ROOT_FOLDER, self.organization, f"{project}", "build-artifacts", f"{runID}"))
                    with open(os.path.join(ROOT_FOLDER, self.organization, project, "build-artifacts", f"{runID}", f"{artifactne}.zip"), "wb") as file:                        
                        file.write(response.content)
                        file.close()
                        if show_output:
                            console.print(border)
                            console.print("[green][+] Artifact Downloaded: {}-{}.zip[/green]".format(artifactne, runID))
                            #console.print(border)
                        if unzip:
                            with ZipFile(os.path.join(ROOT_FOLDER, self.organization, project, "build-artifacts", f"{runID}", f"{artifactne}.zip"), 'r') as zip_ref:
                                zip_ref.extractall(os.path.join(ROOT_FOLDER, self.organization, project, "build-artifacts", f"{runID}"))
                                if show_output:
                                    #console.print(border)
                                    console.print("[green][+] Artifact Extracted: {}-{}.zip[/green]".format(artifactne, runID))
                                    console.print(border)
                else:
                    console.print(f"[red]Error: {response.status_code}[/red]")
                    return
                
    def download_artifacts(self, project, unzip=False, show_output=False) -> None:
        logging.debug("Downloading artifact")
        project = project if project is not None else self.project
        pipeline_runs = self.get_pipeline_runs(project=project)
        #tasks
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Downloading...", total=len(pipeline_runs))
            for pipeline_run in pipeline_runs:
                runID = pipeline_run["id"]
                self.download_artifact(runID=runID, project=project, unzip=unzip, show_output=True)
                progress.update(task, advance=1)

    def download_log(self, build_id, project=None, show_output=False) -> None:
        logging.debug("Downloading log")
        project = project if project is not None else self.project
        self.base_url = f"https://dev.azure.com/{self.organization}/{project}"
        response = self.__make_api_request(f"_apis/build/builds/{build_id}/logs")

        if response and response.status_code == 200:
            response = response.json()
            if response["count"] > 0:
                console.print(border)
                for log in response.get("value", []):
                    log_url = log["url"].split('_apis')[1]
                    log_id = log["id"]

                    response = self.__make_api_request(f"_apis{log_url}")

                    if response and response.status_code == 200:
                        response = response.json()
                        log_data = response["value"]

                        for lines in log_data:
                            #if not os.path.exists(os.path.join(ROOT_FOLDER, self.organization, project, "repos")):
                            # if not os.path.exists(f"{project}/build-logs/{build_id}"):
                            if not os.path.exists(os.path.join(ROOT_FOLDER, self.organization, project, "build-logs", f"{build_id}")):
                                os.makedirs(os.path.join(ROOT_FOLDER, self.organization, project, "build-logs", f"{build_id}"))
                            with open(os.path.join(ROOT_FOLDER, self.organization, project, "build-logs", f"{build_id}", f"{log_id}.log"), "a") as file:
                                file.write(lines + "\n")
                                file.close()
                        if show_output:
                            console.print("[green][+] Log Downloaded: {}-{}.log[/green]".format(build_id, log_id))
                            console.print(border)
        elif response.status_code == 401:
            console.print(f"[red]Unauthorized: The provided token is either invalid or lacks the necessary permissions for this query.[/red]")
        elif response.status_code == 404:
            console.print(f"[red]Build {build_id} has no logs![/red]")
        else:
            console.print(f"[red]Request failed with status code: {response.status_code}[/red]")

    def download_logs(self, project=None, show_output=False) -> None:
        #self.opsec_check("download all pipeline logs")
        
        logging.debug("Downloading logs")

        project = project if project is not None else self.project
        builds = self.get_builds(project=project)

        console.print("[bold][green] Getting build logs... [/green][/bold]")
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Downloading...", total=len(builds))
            for build in builds:
                build_id = build["id"]
                self.download_log(project=project, build_id=build_id, show_output=show_output)
                progress.update(task, advance=1)
        console.print("[green]Mission accomplished! Logs downloaded.[/green]")

    def download_repo(self, repo_ne, project=None, show_output=False, download=False, manual = False) -> None:
        class CloneProgress(RemoteProgress):
            def __init__(self, progress):
                super().__init__()
                self.progress = progress
                self.task_id = self.progress.add_task("Cloning...", total=100)

            def update(self, op_code, cur_count, max_count=None, message=''):
                self.progress.update(self.task_id, advance=cur_count, total=max_count, description=message)
            
        
        logging.debug("Getting repos")
        project = project if project is not None else self.project

        repo_url = f"https://{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"
        clone_dir = os.path.join(ROOT_FOLDER, self.organization, project, "repos", repo_ne)

        if show_output:
            console.print(border)
            console.print(f"[green][+] Repo ne: {repo_ne}[/green]")
            #console.print(f"git clone https://{self.organization}:{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}")
            #console.print(border)
        
        if download:
            try:
                with Progress(console=console) as progress:
                    #console.print(border)
                    console.print(f"[bold][green][+] Downloading Repo: {repo_ne}...[/green][/bold]")
                    Repo.clone_from(repo_url, clone_dir, progress=CloneProgress(progress))
                    console.print(f"\n[bold][green][+] Repo Downloaded: {repo_ne}[/green][/bold]")
                    console.print(border)
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                os.sys.exit(1)
        
        if manual:
            # write to file 
            #clone_command_old = f"git clone https://{self.organization}:{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"
            clone_command = f"git clone https://{self.token}@dev.azure.com/{self.organization}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repo_ne)}"
            git_command_file = os.path.join(ROOT_FOLDER, self.organization, project, "repos", "git-clone-commands.txt")

            if not os.path.exists(os.path.join(ROOT_FOLDER, self.organization, project, "repos")):
                os.makedirs(os.path.join(ROOT_FOLDER, self.organization, project, "repos"))
            with open(f"{git_command_file}", "a") as file:
                file.write(f"{clone_command}\n")
                file.close()
                if show_output:
                    #console.print(border)
                    console.print(f"[bold][green][+] Git Clone Command Saved: {project}/repos/git-clone-commands.txt[/green][/bold]")
                    console.print(border)

        
        
        return "True"
    
    def download_repos(self, project=None, show_output=False, download=False, manual=False, all_projects=False) -> None:
        logging.debug("Downloading repos")

        if all_projects:
            projects = self.get_projects()
            for project in projects:
                project_ne = project["ne"]
                console.print(f"\n[+] Current Project: {project_ne}...\n")
                repos = self.get_repos(project=project_ne)
                for repo in repos:
                    repo_ne = repo["ne"]
                    self.download_repo(repo_ne=repo_ne, project=project_ne, download=download, manual=manual, show_output=True)
        else:
            project = project if project is not None else self.project
            repos = self.get_repos(project=project)

            for repo in repos:
                repo_ne = repo["ne"]
                self.download_repo(repo_ne=repo_ne, project=project, download=download, manual=manual, show_output=True)

############################## EXTRACT / SECRETS ##############################
    def get_group_variables(self, project=None, show_output=False) -> dict:
        logging.debug("Getting group variables")
        project = project if project is not None else self.project
        response = self.__make_api_request(f"{self.project}/_apis/distributedtask/variablegroups")

        group_variables = []

        if response and response.status_code == 200:
            response = response.json()
            if response["count"] > 0:
                for variables in response.get("value", []):
                    for variable in variables.get("variables", []):            
                        varne = variable
                        value = variables['variables'][variable]['value']
                        group_variables.append({"ne": varne, "value": value})
                        if not os.path.exists(os.path.join(ROOT_FOLDER, self.organization, project, "group-variables")):
                            os.makedirs(os.path.join(ROOT_FOLDER, self.organization, project, "group-variables"))
                        with open(os.path.join(ROOT_FOLDER, self.organization, project, "group-variables", "group_variables.json"), "w") as file:
                            file.write(json.dumps(group_variables, indent=2, separators=(',', ':')))
                            file.close()                       
                        if show_output:
                            console.print(border)
                            console.print("[green][+] Variable ne: {}[/green]".format(varne))
                            try:
                                console.print("[green][+] Variable Value: {}[/green]".format(value))
                            except:
                                console.print("[red] Error reading value! [/red]")
                            console.print(border)
            else:
                if show_output:
                    console.print(f"[red][!] No Group Variables Found[/red]")
        else:
            if show_output:
                console.print(f"[red]Error: {response.status_code}[/red]")

        return group_variables

    def get_pipeline_variable(self, pipeline_id, project=None, show_output=False) -> dict:
        logging.debug("Getting pipeline variables")
        project = project if project is not None else self.project
        pipeline_variables = []
        response = self.__make_api_request(f"{project}/_apis/build/Definitions/{pipeline_id}")
        if response and response.status_code == 200:
            response = response.json()
            variables = response.get("variables", [])
            if variables:
                for ne, value in variables.items():
                    pipeline_variables.append({"ne": ne, "value": value.get("value")})
                    if show_output:
                        console.print(border)
                        console.print("[green][+] Variable ne: {}[/green]".format(ne))
                        console.print("[green][+] Variable Value: {}[/green]".format(value.get("value")))
                        console.print(border)
        return pipeline_variables

    def get_pipeline_variables(self, project=None, show_output=False) -> dict:
        logging.debug("Getting pipeline variables")
        project = project if project is not None else self.project
        pipeline_variables = []
        pipelines = self.get_pipelines(project=project)

        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Downloading...", total=len(pipelines))
            for pipeline in pipelines:
                pipeline_id = pipeline["id"]
                pipeline_variable = self.get_pipeline_variable(pipeline_id=pipeline_id, project=project, show_output=show_output)
                #path = os.path.join(ROOT_FOLDER, self.organization, project, "pipeline-variables", f"{pipeline_id}_pipeline_variables.json") 
                if not os.path.exists(os.path.join(ROOT_FOLDER, self.organization, project, "pipeline-variables")):
                    os.makedirs(os.path.join(ROOT_FOLDER, self.organization, project, "pipeline-variables"))
                with open(os.path.join(ROOT_FOLDER, self.organization, project, "pipeline-variables", f"{pipeline_id}_pipeline_variables.json"), "w") as file:
                    json.dump(pipeline_variable, file, indent=4)
                    file.close()
                    if show_output:
                        console.print(border)
                        console.print("[bold][green][+] Pipeline Variables Saved: {}/{}/{}_pipeline_variables.json[/green]".format(project,"pipeline-variables",pipeline_id))
                        console.print(border)
                progress.update(task, advance=1)
                pipeline_variables.append(pipeline_variable)
        
        return pipeline_variables

    def get_secure_files(self, project=None, show_output=False) -> dict:
        logging.debug("Getting secure files")
        project = project if project is not None else self.project
        secure_files = []
        response = self.__make_api_request(f"{project}/_apis/distributedtask/securefiles")
        if response and response.status_code == 200:
            response = response.json()
            if response["count"] > 0:
                for secure_file in response.get("value", []):
                    secure_files.append({"ne": secure_file["ne"], "id": secure_file["id"]})
                    if show_output:
                        console.print(border)
                        console.print("[green][+] Secure File ne: {}[/green]".format(secure_file["ne"]))
                        console.print("[green][+] Secure File ID: {}[/green]".format(secure_file["id"]))
                        console.print(border)
            else:
                if show_output:
                    console.print(f"[red][!] No Secure Files Found[/red]")
        
        return secure_files

    def get_service_connections(self, project=None, show_output=False) -> dict:
        logging.debug("Getting service connections")
        project = project if project is not None else self.project
        service_connections = []
        response = self.__make_api_request(f"{project}/_apis/serviceendpoint/endpoints")
        if response and response.status_code == 200:
            response = response.json()
            #print(f"{response}")
            if response["count"] > 0:
                for service_connection in response.get("value", []):
                    service_connections.append({"ne": service_connection["ne"], "id": service_connection["id"]})
                    if show_output:
                        console.print(border)
                        console.print(f"[green][+] Service Connection ne: {service_connection["ne"]}[/green]")
                        console.print(f"[green][+] Service Type: {service_connection["type"]}[/green]")
                        console.print(f"[green][+] Service Connection ID: {service_connection["id"]}[/green]")
                        console.print(f"[green][+] Service URL: {service_connection["url"]}[/green]")
                        console.print(f"[green][+] Service Authorization Scheme: {service_connection["authorization"]["scheme"]}[/green]")
                        console.print(border)
            else:
                if show_output:
                    console.print(f"[red][!] No Service Connections Found[/red]")
        
        return service_connections

class AzureDevOpsCLIHandler:
    def __init__(self):
        self.app = typer.Typer(add_completion=False,
                               rich_markup_mode='rich', 
                               context_settings={'help_option_nes': ['-h', '--help', 'help']}, 
                               pretty_exceptions_show_locals=False, help="[bold][cyan]Zeus - Azure DevOps Recon Tool[/cyan]")
        self.enum_app = typer.Typer(help="Enumeration Module")
        self.extract_app = typer.Typer(help="Extraction Module")
        self.secrets_app = typer.Typer(help="Secrets Module")
        self.download_app = typer.Typer(help="Download Module")
        self.org_app = typer.Typer(help="Organization Module")
        self.project_app = typer.Typer(help="Projects Module")
        self.setup_apps()
        self.setup_enum_commands()
        self.setup_extract_commands()

    def setup_apps(self):
        # Main Modules
        self.app.add_typer(self.enum_app, ne="enum")
        self.app.add_typer(self.extract_app, ne="extract")

        # Enumeration Modules
        self.enum_app.add_typer(self.org_app, ne="org")
        self.enum_app.add_typer(self.project_app, ne="project")

        # Extraction Modules
        self.extract_app.add_typer(self.secrets_app, ne="secrets")
        self.extract_app.add_typer(self.download_app, ne="download")

    def setup_enum_commands(self):

        ############################## ENUM / ORGANIZATION ##############################

        @self.org_app.command(help="Enumerate Personal Access Token Information (whoami)")
        def token(
        # Authentication Options
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options', show_default=False),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),

        # Misc Options
        debug: bool = typer.Option(False, '--debug', help='Turn DEBUG output ON', rich_help_panel='Misc Options'),
        output: bool = typer.Option(False, '--output-dir', help='Directory so save output', rich_help_panel='Misc Options'),
        quiet: bool = typer.Option(False, '--quiet', help='Hide the banner', rich_help_panel='Misc Options')
        ):
            
            client = AzureDevopsClient(token=token, organization=org)
            token_info = client.token_info()
            console.print(border)
            typer.echo(f"[+] Display ne: {token_info['displayne']}")
            typer.echo(f"[+] Account: {token_info['account']}")
            typer.echo(f"[+] ID: {token_info['id']}")
            console.print(border)

        @self.org_app.command(help="Enumerate Current PAT Scope")
        def pat_scope(
        # Authentication Options
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options', show_default=False),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        ):
            
            client = AzureDevopsClient(token=token, organization=org)
            token_info = client.get_token_scopes(show_output=True)
        
        @self.org_app.command(help="Enumerate Current User's PATs")
        def user_tokens(
        # Authentication Options
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options', show_default=False),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        ):
            
            client = AzureDevopsClient(token=token, organization=org)
            token_info = client.get_user_pats(show_output=True)
        
        @self.org_app.command(help="Enumerate User Public SSH Key Information")
        def ssh_keys(
        # Authentication Options
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options', show_default=False),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        ):
            
            client = AzureDevopsClient(token=token, organization=org)
            token_info = client.get_user_ssh_keys(show_output=True)

        @self.org_app.command(help="Enumerate Users in Organization")
        def users(
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options', show_default=False),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options', show_default=False),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_users(show_output=True)

        @self.org_app.command(help="Enumerate Projects in Organization")
        def projects(
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
    ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_projects(show_output=True)

        @self.org_app.command(help="Enumerate Groups in Organization")
        def groups(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options')
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_groups(show_output=True)

        # @self.org_app.command(help="Enumerate Group Members in Organization")
        # def group_memberss(
        #     token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
        #     org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options')
        # ):
        #     client = AzureDevopsClient(token=token, organization=org)
        #     client.get_group_members(show_output=True)

        @self.org_app.command(help="Enumerate Teams in Organization")
        def teams(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options')
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_teams(show_output=True)

        @self.org_app.command(help="Enumerate Security (nespace) Permissions [red](Not yet implemented!)[/red]")
        def nespace_permissions(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options')
        ):
            client = AzureDevopsClient(token=token, organization=org)
            #client.get_nespace_permissions(show_output=True)
            console.print("[red]Not yet implemented![/red]")

        ############################## ENUM / PROJECTS ##############################
          
        @self.project_app.command(help="Enumerate Project Admins")
        def project_admins(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options')
        ):
            console.print("[red]Not yet implemented[/red]")
            #client = AzureDevopsClient(token=token, organization=org, project=project)
            #client.get_project_admins(show_output=True)

        @self.project_app.command(help="Enumerate Project Repositories")
        def repos(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
            download: bool = typer.Option(False, '--download', help='Download ALL Repos', rich_help_panel='Repo Options'),
            manual: bool = typer.Option(False, '--manual', help='Git Clone CLI Helper', rich_help_panel='Repo Options'),
            all: bool = typer.Option(False, '--all', help='Target ALL Projects', rich_help_panel='Project Options')
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_repos(project=project, download=download, manual=manual, all_projects=all, show_output=True)

        @self.project_app.command(help="Enumerate Project Pipelines")
        def pipelines(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_pipelines(project=project, show_output=True)

        @self.project_app.command(help="Enumerate Project Pipeline Runs")
        def pipeline_runs(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_pipeline_runs(project=project, show_output=True)

        @self.project_app.command(help="Enumerate Project Build Definitions")
        def definitions(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_defintions(project=project, show_output=True)

        @self.project_app.command(help="Enumerate Project Builds")
        def builds(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_builds(project=project, show_output=True)

        @self.project_app.command(help="Enumerate All Build Run Artifacts within project.")
        def build_artifacts(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_build_artifacts(project=project)

        @self.project_app.command(help="Enumerate Build Run Artifact for specific build id.")
        def build_artifact(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            id: str = typer.Option(None, '--id', '-i', help='Build ID', rich_help_panel='Project Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_artifact(runID=id, project=project, show_output=True)

        @self.project_app.command(help="Search Code in Project Repositories")
        def code_search(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
            search: str = typer.Option(None, '--search', '-s', help='Search Text', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            #client.code_search(project=project, searchText=search, show_output=True)
            console.print("[red]Not yet implemented![/red]")

        @self.project_app.command(help="Enumerate Project Group Members")
        def group_members(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org)
            client.get_project_group_permissions(project=project, show_output=True)

    def setup_extract_commands(self):

        ############################## EXTRACT / DOWNLOAD ##############################
        @self.download_app.command(help="Download Project Repository Zip")
        def repo(
            token: str = typer.Option(..., '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(..., '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(..., '--project', '-p', help='Project', rich_help_panel='Project Options'),
            repo: str = typer.Option('', '--repo', '-r', help='Repository', rich_help_panel='Project Options'),
            manual: bool = typer.Option(False, '--manual', help='Get Git Clone Command', rich_help_panel='Project Options'),
            download: bool = typer.Option(False, '--download', help='Download Repo', rich_help_panel='Project Options'),
            all_repos: bool = typer.Option(False, '--all-repos', help='Target all repos current project', rich_help_panel='Project Options'),
            all_projects: bool = typer.Option(False, '--all-projects', help='Target all repos for all projects', rich_help_panel='Project Options'),

        ):
            client = AzureDevopsClient(token=token, organization=org, project=project)
            if all_repos:
                client.download_repos(project=project, download=download, manual=manual, show_output=True)
            elif all_projects:
                client.download_repos(project=project, download=download, manual=manual, all_projects=all_projects, show_output=True)
            else:
                client.download_repo(repo_ne=repo, download=download, manual=manual, show_output=True)

        @self.download_app.command(help="Download Pipeline Run Artifact (Zip)")
        def artifact(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
            id: str = typer.Option(None, '--id', '-b', help='Pipeline Run ID [enum project builds]', rich_help_panel='Project Options'),
            unzip: bool = typer.Option(None, '--unzip', '-u', help='Unzip artifacts once  downloaded', rich_help_panel='Project Options'),
            all: bool = typer.Option(None, '--all', '-a', help='Download All Pipeline Run Artifacts for a Project', rich_help_panel='Project Options')
        ):
            client = AzureDevopsClient(token=token, organization=org, project=project)
            if all:
                client.download_artifacts(project=project, unzip=unzip, show_output=True)
            else:
                client.download_artifact(id, project=project, unzip=unzip, show_output=True)

        # @self.download_app.command(help="Download All Pipeline Run Artifacts for a Project")
        # def artifacts(
        #     token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
        #     org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        #     project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        #     unzip: str = typer.Option(None, '--unzip', '-u', help='Unzip artifacts once  downloaded', rich_help_panel='Project Options'),
        # ):
        #     client = AzureDevopsClient(token=token, organization=org, project=project)
        #     client.download_artifacts(project=project, unzip=unzip, show_output=True)

        @self.download_app.command(help="Download Project Pipeline Run Logs")
        def logs(
            token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options', show_default=False),
            org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options', show_default=False),
            build_id: str = typer.Option(None, '--build-id', '-i', help='Pipeline Run ID [bold][green](cmd: enum project builds)[/bold][/green]', rich_help_panel='Project Options', show_default=False),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options', show_default=False),
            all: bool = typer.Option(False, '--all', help='Target ALL Logs', rich_help_panel='Project Options'),
        ):
            client = AzureDevopsClient(token=token, organization=org, project=project)
            if all:
                client.download_logs(show_output=True)
            else:
                client.download_log(build_id=build_id, show_output=True)

        ############################## EXTRACT / SECRETS ##############################
        @self.secrets_app.command(help="Extract Group Variables")
        def group_variables(
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
    ):
            client = AzureDevopsClient(token=token, organization=org, project=project)
            client.get_group_variables(show_output=True)

        @self.secrets_app.command(help="Extract Pipeline Variables")
        def pipeline_variable(
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        defintion_id: str = typer.Option(None, '--definition-id', '-i', help='Definition ID', rich_help_panel='Project Options')
    ):
            client = AzureDevopsClient(token=token, organization=org, project=project)
            client.get_pipeline_variable(defintion_id, show_output=True)

        @self.secrets_app.command(help="Extract All Pipeline Variables")
        def pipeline_variables(
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
    ):
            client = AzureDevopsClient(token=token, organization=org, project=project)
            client.get_pipeline_variables(show_output=True)

        @self.secrets_app.command(help="Enumerate Secure Files")
        def secure_files(
        token: str = typer.Option(None, '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
        org: str = typer.Option(None, '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
        project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
    ):
            client = AzureDevopsClient(token=token, organization=org, project=project)
            client.get_secure_files(show_output=True)

        @self.secrets_app.command(help="Enumerate Service Connections")
        def service_connections(
            token: str = typer.Option('', '--token', '-t', help='Personal Access Token', rich_help_panel='Authentication Options'),
            org: str = typer.Option('', '--org', '-o', help='Organization', rich_help_panel='Authentication Options'),
            project: str = typer.Option(None, '--project', '-p', help='Project', rich_help_panel='Project Options'),
        ):
            #console.print(f"[red]Not yet implemented[/red]")
            client = AzureDevopsClient(token=token, organization=org, project=project)
            client.get_service_connections(show_output=True)

    def main_callback(self):
        # This function will execute before any command
        print("Missing args, try --help")
    
    def run(self):
        #self.app.callback(no_args_is_help=True)(self.main_callback)
        self.app()

zeus_ascii = pyfiglet.figlet_format("   Zeus", font="slant")
azure_ascii = pyfiglet.figlet_format("Azure DevOps Recon Tool", font="digital", )
version = "\t" * 5 + "v0.0.1"
ascii_banner = zeus_ascii + azure_ascii + f"\n{version}\n"

if __ne__ == "__main__":
    if True == True:
        print(ascii_banner)
    cli_handler = AzureDevOpsCLIHandler()
    cli_handler.run()