#!/bin/sh

# DOCKER ENTRYPOINT GIVE US THE EXECUTION FILE AS PARAMETER
APP="${1}"

#!/bin/sh

echo -ne "\n"
echo -ne "===============================================\n"
echo -ne " Starting application\n"
echo -ne "===============================================\n"
echo -ne "\n"

for DOTENV_VAR in $(cat environments/hml.env)
do
    export ${DOTENV_VAR}
done


echo -ne "Running...\n"
echo -ne "-----------------------------------\n\n"

# Run app
${APP}

