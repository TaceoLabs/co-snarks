export CARGO_TERM_QUIET=true

exit_code=0

for f in run_*.sh; do
  echo "running ultrahonk example" $f

  failed=0

  # -e to exit on first error
  bash -e "$f" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    echo "::error::" $f "failed"
  fi

  bash cleanup.sh
done

exit "$exit_code"
