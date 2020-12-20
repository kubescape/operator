rm -rf *tests_xunit.xml
rm -rf *_tests_go.txt
# get directories with sub dirs
dirslist=$(find -type d -printf '%d\t%P\n' | sort -r -nk1 | cut -f2-)
for path in $dirslist; do
    [ -d "${path}" ] || continue # if not a directory, skip  
    [[ $path == '.'* ]] && continue  # if hidden directory, skip
    [[ $path == 'jenkinstools'* ]] && continue  # if jenkinstools subdirectory, skip
    dirname="./"$path
    basename="$(basename "${path}")"
    if [[ $dirname == *"jenkinstools"* ]]    || [[ $dirname == *"dist"* ]] || [[ $dirname == *"vendor"* ]] || [[ $dirname == "src" ]] || [[ $dirname == "pkg" ]] || [[ $dirname == "bin" ]]; then
        continue
    fi
    echo testing "${dirname}"
    go test -v ./$dirname  > ${basename}_tests_go.txt
    cat  ${basename}_tests_go.txt | $GOPATH/bin/go2xunit >${basename}_tests_xunit.xml
done
TESTS_FAILED=$(find -type f -name "*.txt" -exec grep -l 'FAIL' {} +)
if [ -z "${TESTS_FAILED}" ]; then 
    echo "<---------------GOLANG Tests passed:---------------------->"
    echo $TESTS_FAILED
    exit 1
else
    echo "GOLANG Failed tests: $TESTS_FAILED"
fi