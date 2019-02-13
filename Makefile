all:
	tinker -b

serve:
	python3 -m http.server 8089

# Update the artifacts reference page.
artifacts:
	python scripts/artifact_docs.py ~/go/src/www.velocidex.com/golang/velociraptor/artifacts/definitions/ > reference/artifacts.rst
