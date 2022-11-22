FROM golang:1.18-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY go.sum ./

RUN go mod download
COPY ./ ./

RUN CGO_ENABLED=0 go build -o /ctf-reset-password cmd/main.go

FROM golang:1.18-alpine

ENV APP_HOME /go/src/ctf-reset-password
RUN mkdir -p "$APP_HOME"
WORKDIR "$APP_HOME"

COPY static/ static/
COPY --from=build /ctf-reset-password $APP_HOME

EXPOSE 80

ENTRYPOINT ["./ctf-reset-password"]
