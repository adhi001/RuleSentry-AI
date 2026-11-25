FROM node:22-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package.json ./
RUN npm install
COPY frontend/index.html frontend/vite.config.js ./
COPY frontend/src ./src
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY rulesentry ./rulesentry
RUN pip install --no-cache-dir .
COPY --from=frontend-build /frontend/dist ./frontend/dist
EXPOSE 8000
CMD ["uvicorn", "rulesentry.main:app", "--host", "0.0.0.0", "--port", "8000"]
