all:
	tinker -b

serve:
	python3 -m http.server

# Update the artifacts reference page.
artifacts:
	python scripts/artifact_docs.py ~/go/src/www.velocidex.com/golang/velociraptor/artifacts/definitions/ > reference/artifacts.rst
