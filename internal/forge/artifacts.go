package forge

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"time"
)

type Artifact struct {
	Filename string
	Content  []byte
}

func buildArtifact(itemType, name, theme, httpsURL, dnsName string, platforms []string) (*Artifact, error) {
	switch itemType {
	case "env":
		return buildEnv(name, theme, httpsURL, dnsName)
	case "svg":
		return buildSVG(name, httpsURL)
	case "html":
		return buildHTML(name, theme, httpsURL)
	case "docx":
		return buildDOCX(name, theme, httpsURL)
	case "xlsx":
		return buildXLSX(name, theme, httpsURL)
	case "pdf":
		return buildPDF(name, theme, httpsURL, dnsName)
	case "folder":
		return buildFolder(name, theme, httpsURL, dnsName)
	case "stub-exe":
		return buildStubExe(name, httpsURL, platforms)
	default:
		return nil, fmt.Errorf("unsupported type %q (env|svg|html|docx|xlsx|pdf|folder|stub-exe)", itemType)
	}
}

func buildEnv(name, theme, httpsURL, dnsName string) (*Artifact, error) {
	var b strings.Builder
	b.WriteString("# " + name + " - decoy credentials (inert)\n")
	b.WriteString("# AUTHORIZED TRIPWIRE - not real secrets\n")
	b.WriteString(themeFiller(theme, name))
	b.WriteString(fmt.Sprintf("APP_ENV=staging\n"))
	b.WriteString(fmt.Sprintf("DATABASE_URL=postgres://canary_user:not-a-real-password-%s@db.example.invalid:5432/app\n", randomPadding(6)))
	b.WriteString(fmt.Sprintf("AWS_ACCESS_KEY_ID=AKIA%s\n", strings.ToUpper(randomPadding(16))))
	b.WriteString(fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s\n", randomPadding(40)))
	if httpsURL != "" {
		b.WriteString("# healthcheck\nHEALTHCHECK_URL=" + httpsURL + "\n")
	}
	if dnsName != "" {
		b.WriteString("# resolver probe host\nMETRICS_HOST=" + dnsName + "\n")
	}
	b.WriteString("# pad:" + randomPadding(32+randomInt(64)) + "\n")
	return &Artifact{Filename: sanitizeName(name) + ".env", Content: []byte(b.String())}, nil
}

func buildSVG(name, httpsURL string) (*Artifact, error) {
	if httpsURL == "" {
		return nil, fmt.Errorf("svg requires --collector HTTPS URL")
	}
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 %d %d">
  <title>%s</title>
  <desc>%s</desc>
  <image href="%s" x="0" y="0" height="0" width="0"/>
</svg>
`, 100+randomInt(400), 80+randomInt(300), xmlEscape(name), xmlEscape(randomPadding(12)), xmlEscape(httpsURL))
	return &Artifact{Filename: sanitizeName(name) + ".svg", Content: []byte(body)}, nil
}

func buildHTML(name, theme, httpsURL string) (*Artifact, error) {
	if httpsURL == "" {
		return nil, fmt.Errorf("html requires --collector HTTPS URL")
	}
	body := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>%s</title>
<meta name="generator" content="%s">
</head><body>
<h1>%s</h1>
<pre>%s</pre>
<img src="%s" width="1" height="1" alt="">
</body></html>
`, xmlEscape(name), xmlEscape(randomPadding(8)), xmlEscape(name), xmlEscape(themeFiller(theme, name)), xmlEscape(httpsURL))
	return &Artifact{Filename: sanitizeName(name) + ".html", Content: []byte(body)}, nil
}

func buildDOCX(name, theme, httpsURL string) (*Artifact, error) {
	if httpsURL == "" {
		return nil, fmt.Errorf("docx requires --collector HTTPS URL")
	}
	created := randomPastTime()
	modified := created.Add(time.Duration(randomInt(72)) * time.Hour)
	core := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>%s</dc:title>
  <dc:creator>%s</dc:creator>
  <cp:lastModifiedBy>%s</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>
</cp:coreProperties>`, xmlEscape(name), xmlEscape("Ops "+randomPadding(4)), xmlEscape("Reviewer "+randomPadding(3)),
		created.Format(time.RFC3339), modified.Format(time.RFC3339))

	doc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
    <w:p><w:r><w:t>%s</w:t></w:r></w:p>
    <w:p><w:r><w:t>%s</w:t></w:r></w:p>
    <w:p>
      <w:r>
        <w:drawing>
          <wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
            <a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
              <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
                <pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
                  <pic:blipFill><a:blip r:embed="rId1"/></pic:blipFill>
                </pic:pic>
              </a:graphicData>
            </a:graphic>
          </wp:inline>
        </w:drawing>
      </w:r>
    </w:p>
    <w:sectPr/>
  </w:body>
</w:document>`, xmlEscape(name), xmlEscape(themeFiller(theme, name)))

	rels := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>
</Relationships>`, xmlEscape(httpsURL))

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`

	rootRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	files := map[string]string{
		"[Content_Types].xml":          contentTypes,
		"_rels/.rels":                  rootRels,
		"word/document.xml":            doc,
		"word/_rels/document.xml.rels": rels,
		"docProps/core.xml":            core,
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &Artifact{Filename: sanitizeName(name) + ".docx", Content: buf.Bytes()}, nil
}

func buildXLSX(name, theme, httpsURL string) (*Artifact, error) {
	if httpsURL == "" {
		return nil, fmt.Errorf("xlsx requires --collector HTTPS URL")
	}
	created := randomPastTime()
	core := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>%s</dc:title>
  <dc:creator>%s</dc:creator>
  <dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>
</cp:coreProperties>`, xmlEscape(name), xmlEscape("Analyst "+randomPadding(4)), created.Format(time.RFC3339))

	sheet := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheetData>
    <row r="1"><c r="A1" t="inlineStr"><is><t>%s</t></is></c></row>
    <row r="2"><c r="A2" t="inlineStr"><is><t>%s</t></is></c></row>
  </sheetData>
  <drawing r:id="rId1"/>
</worksheet>`, xmlEscape(name), xmlEscape(strings.ReplaceAll(themeFiller(theme, name), "\n", " ")))

	// External image relationship for beacon (Office fetch).
	sheetRels := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>
</Relationships>`, xmlEscape(httpsURL))

	workbook := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>`
	wbRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`
	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`
	rootRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	files := map[string]string{
		"[Content_Types].xml":                 contentTypes,
		"_rels/.rels":                         rootRels,
		"xl/workbook.xml":                     workbook,
		"xl/_rels/workbook.xml.rels":          wbRels,
		"xl/worksheets/sheet1.xml":            sheet,
		"xl/worksheets/_rels/sheet1.xml.rels": sheetRels,
		"docProps/core.xml":                   core,
	}
	for n, c := range files {
		w, err := zw.Create(n)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(c)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &Artifact{Filename: sanitizeName(name) + ".xlsx", Content: buf.Bytes()}, nil
}

func buildPDF(name, theme, httpsURL, dnsName string) (*Artifact, error) {
	// Minimal PDF with a URI action / link annotation. Prefer HTTPS; DNS hostname
	// embedded in text for resolvers that scan document strings.
	target := httpsURL
	if target == "" && dnsName != "" {
		target = "https://" + dnsName + "/"
	}
	if target == "" {
		return nil, fmt.Errorf("pdf requires --collector or --collector-dns")
	}
	text := strings.ReplaceAll(themeFiller(theme, name), "(", "\\(")
	text = strings.ReplaceAll(text, ")", "\\)")
	// Simple single-page PDF.
	var body strings.Builder
	body.WriteString("%PDF-1.4\n")
	body.WriteString("%" + string(randomBytes(4)) + "\n")
	objects := []string{
		"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n",
		"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n",
		fmt.Sprintf("3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> /Annots [6 0 R] >>endobj\n", 612, 792),
		fmt.Sprintf("4 0 obj<< /Length %d >>stream\nBT /F1 12 Tf 72 720 Td (%s) Tj ET\nendstream\nendobj\n", 40+len(text), text),
		"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
		fmt.Sprintf("6 0 obj<< /Type /Annot /Subtype /Link /Rect [72 700 300 740] /A<< /S /URI /URI (%s) >> >>endobj\n", target),
	}
	offsets := []int{0}
	for _, obj := range objects {
		offsets = append(offsets, body.Len())
		body.WriteString(obj)
	}
	xrefStart := body.Len()
	body.WriteString(fmt.Sprintf("xref\n0 %d\n", len(objects)+1))
	body.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		body.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}
	body.WriteString(fmt.Sprintf("trailer<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefStart))
	return &Artifact{Filename: sanitizeName(name) + ".pdf", Content: []byte(body.String())}, nil
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "tripwire"
	}
	repl := strings.NewReplacer("/", "_", "\\", "_", " ", "-", "..", ".")
	return repl.Replace(name)
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
}
