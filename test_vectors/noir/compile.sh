## script to compile all circuits and witnesses with the specified nargo version below

script_dir="$(dirname "$(realpath "$0")")"

NARGO_VERSION=1.0.0-beta.14 ##specify the desired nargo version here

## install noirup: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
r=$(bash -c "nargo --version")
if  [[ $r != "nargo version = $NARGO_VERSION"* ]];
then
    bash -c "noirup -v ${NARGO_VERSION}"
fi

for folder in "$script_dir"/*; do

    if [ -d "$folder" ]; then
        echo "Processing folder: $folder"


        cd "$folder" || { echo "Failed to enter folder $folder"; continue; }


        echo "Executing commands in $folder"

        nargo execute

        if [ -d "target" ] && [ -d "kat" ]; then
            echo "Moving files from target to kat in $folder"
            mv -f target/* kat/ 2>/dev/null || echo "No files to move or failed to move files"
        else
            echo "Either 'target' or 'kat' subfolder is missing in $folder"
        fi

        # Return to the script directory
        cd "$script_dir" || { echo "Failed to return to script directory"; exit 1; }
    fi

done

echo "All folders processed."
