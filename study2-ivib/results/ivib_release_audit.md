# What the released IVIB code contains (github.com/KLSEHB/IVIB, checked 2026-10-31)

| Part | Status in the release | Evidence |
|---|---|---|
| Source/sink lists | present, method names only, no sanitisers | Constants.java: 22 quoted names |
| Slicing traversals | stubs returning empty sets | TranslateServiceImpl.java lines 86 90 |
| prune() / translate() calls | commented out | SlicingServiceImpl.java: 2 commented calls |
| ISL writer | writes an empty string | ParseFileServiceImpl.writeTranslateResult has an empty body |
| Vulnerability classes | sqlvul, xssvul, cmdvul, xpathvul (no path traversal, no code injection) | config/properties.py TAG2IDX |
| BERT-BiLSTM-CRF model + training code | complete | mycode/a_超参数训练/model.py, train.py |
| Data, slices, trained model | not included | experiment/resource/{data,model} are empty |
| Paths | hard-coded Windows (D:\\...) and /home/dixu | application.properties, experiment.properties |
