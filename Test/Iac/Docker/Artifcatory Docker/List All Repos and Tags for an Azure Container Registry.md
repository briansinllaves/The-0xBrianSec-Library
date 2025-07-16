```
#!/bin/bash
# written by brian
#
############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "Enumerate all images and tags for a given Azure Container Registry."
   echo
   echo "Syntax: azurecrenum [-h|r|u|p]"
   echo "options:"
   echo "h     Help."
   echo "r     AzureCR URI. i.e. myacr.azurecr.io"
   echo "u     Userne."
   echo "p     Password."
   echo
}

############################################################
############################################################
# Main program                                             #
############################################################
############################################################



while getopts ":hr:u:p:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      r) # Enter a URI
         URI=$OPTARG;;
      u) # Userne 
         USER=$OPTARG;;
      p)
         PASSWORD=$OPTARG;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done


REQ=$(curl -s -L --user "$USER:$PASSWORD" "https://$URI/v2/_catalog" | jq '.repositories | @sh' | tr -d \')
declare -a REPOS="($REQ)"

for i in $REPOS
do
   REQ=$(curl -s -L --user "$USER:$PASSWORD" "https://$URI/v2/$i/tags/list" | jq '.tags | @sh' | tr -d \')
   declare -a TAGS="($REQ)"
   for n in $TAGS
   do
      echo "$i:$n"
   done
done
```