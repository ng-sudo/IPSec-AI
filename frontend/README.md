# IPSecAI Dashboard

React dashboard for the IPSecAI FastAPI analysis API.

## Run

Start the backend first, then run:

```bash
npm install
npm run dev
```

Open `http://localhost:5173`.

The API defaults to `http://127.0.0.1:8000`. Override it with `VITE_API_URL` when needed:

```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

## Checks

```bash
npm test
npm run build
```

The dashboard does not contain sample analysis results. It displays only backend responses and marks missing values as unavailable.
