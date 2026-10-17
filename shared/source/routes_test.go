package source

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func routeSet(rs []Route) map[string]Route {
	out := map[string]Route{}
	for _, r := range rs {
		out[r.Method+" "+r.Pattern] = r
	}
	return out
}

func TestExpressRoutes(t *testing.T) {
	src := `const express = require('express');
const axios = require('axios');
const app = express();
const api = express.Router();
const admin = express.Router();
app.get('/', (req, res) => res.send('ok'));
app.post("/login", rateLimit, (req, res) => {});
api.get('/accounts/:id', requireAuth, async (req, res) => {});
api.delete('/accounts/:id/sessions/:sid?', handler);
admin.put('/users/:id', authenticate, update);
app.use('/api', api);
axios.get('/api/accounts/1');
cache.get('/not-a-route');
app.get(` + "`/v1/${version}/x`" + `, handler);
app.get(` + "`/static`" + `, handler);
app.all('/health/', handler);
`
	got := routeSet(extractRoutes("server/app.js", []byte(src)))
	want := map[string][2]string{
		"GET /":                         {"not assessed", "medium"},
		"POST /login":                   {"not assessed", "medium"},
		"GET /api/accounts/{parameter}": {"auth_middleware_named", "medium"},
		"DELETE /api/accounts/{parameter}/sessions/{parameter}": {"not assessed", "medium"},
		"PUT /users/{parameter}":                                {"auth_middleware_named", "low"},
		"GET /static":                                           {"not assessed", "medium"},
		"ALL /health":                                           {"not assessed", "medium"},
	}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for k, v := range want {
		r, ok := got[k]
		if !ok || r.Auth != v[0] || r.Confidence != v[1] || r.Origin != "declared_route" || r.Path != "server/app.js" {
			t.Fatal(k, r, ok)
		}
	}
	if extractRoutes("server/app.test.js", []byte(src)) != nil || extractRoutes("types/app.d.ts", []byte(src)) != nil {
		t.Fatal("test or declaration file read as routes")
	}
	if extractRoutes("client.js", []byte(`import axios from "axios"; axios.get("/api/x"); const app = {}; app.get("/y")`)) != nil {
		t.Fatal("non-express receiver read as routes")
	}
}

func TestFastAPIRoutes(t *testing.T) {
	src := `from fastapi import FastAPI, APIRouter, Depends
app = FastAPI()
router = APIRouter(prefix="/items", tags=["items"])
other = APIRouter()
data = {}

@app.get("/")
def root():
    return {}

@router.get("/{item_id}")
async def read_item(item_id: int, user = Depends(get_current_user)):
    return data.get("/x")

@router.post("", dependencies=[Depends(rate_limit)])
async def create():
    pass

@other.api_route("/both", methods=["GET", "POST"])
def both():
    pass

@app.route("/ignored")
def starlette_style():
    pass
`
	got := routeSet(extractRoutes("api/main.py", []byte(src)))
	want := map[string][2]string{
		"GET /":                  {"not assessed", "medium"},
		"GET /items/{parameter}": {"auth_middleware_named", "medium"},
		"POST /items":            {"not assessed", "medium"},
		"GET /both":              {"not assessed", "low"},
		"POST /both":             {"not assessed", "low"},
	}
	if !reflect.DeepEqual(keys(got), keys(map2(want))) {
		t.Fatal(got)
	}
	for k, v := range want {
		if r := got[k]; r.Auth != v[0] || r.Confidence != v[1] {
			t.Fatal(k, r)
		}
	}
}

func TestFlaskRoutes(t *testing.T) {
	src := `from flask import Flask, Blueprint
from flask_login import login_required
app = Flask(__name__)
bp = Blueprint("admin", __name__, url_prefix="/admin")

@app.route("/")
def index():
    return "ok"

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    pass

@bp.route("/users/<int:user_id>", methods=("DELETE",))
def delete(user_id):
    pass

@bp.get("/reports")
def reports():
    pass

@app.route("/dyn", methods=METHODS)
def dyn():
    pass
`
	got := routeSet(extractRoutes("web/app.py", []byte(src)))
	want := map[string]string{
		"GET /":                           "not assessed",
		"GET /upload":                     "auth_middleware_named",
		"POST /upload":                    "auth_middleware_named",
		"DELETE /admin/users/{parameter}": "not assessed",
		"GET /admin/reports":              "not assessed",
		"unknown /dyn":                    "not assessed",
	}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for k, v := range want {
		if r, ok := got[k]; !ok || r.Auth != v || r.Confidence != "medium" {
			t.Fatal(k, r, ok)
		}
	}
}

func TestPythonFrameworksAndInventory(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("Flask==3.0.0\nrequests\n"), 0644)
	os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[project]\ndependencies = [\"fastapi>=0.110\"]\n"), 0644)
	os.WriteFile(filepath.Join(root, "app.py"), []byte("from flask import Flask\napp = Flask(__name__)\n@app.route('/ping')\ndef ping():\n    return 'pong'\n"), 0644)
	m, e := Read(root, "app_demo")
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(m.Frameworks, []string{"fastapi", "flask"}) || len(m.Routes) != 1 || m.Routes[0].Pattern != "/ping" || m.Routes[0].Method != "GET" {
		t.Fatal(m.Frameworks, m.Routes)
	}
	if len(m.Extractors) != 4 {
		t.Fatal(m.Extractors)
	}
	again, _ := Read(root, "app_demo")
	if again.Digest != m.Digest {
		t.Fatal("route extraction is not deterministic")
	}
}

func TestRouteBudgetPerFile(t *testing.T) {
	src := "const express = require('express')\nconst app = express()\n"
	for i := 0; i < maxRoutesPerFile+50; i++ {
		src += fmt.Sprintf("app.get('/r%d', h)\n", i)
	}
	if n := len(extractRoutes("big.js", []byte(src))); n != maxRoutesPerFile {
		t.Fatal(n)
	}
}

func keys(m map[string]Route) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}
func map2(m map[string][2]string) map[string]Route {
	out := map[string]Route{}
	for k := range m {
		out[k] = Route{}
	}
	return out
}
func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
