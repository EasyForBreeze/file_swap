# Используем официальный образ .NET 9.0 SDK для сборки
FROM nexus.ahml.ru/docker-hosted-auth/dom_assistant_new/dotnet-sdk:9.0 AS build
WORKDIR /src

# 1) Копируем csproj и nuget.config (офлайн-режим: без внешних источников)
COPY ["new_assistant.csproj", "./"]
COPY ["nuget.config", "./"]

# 2) Копируем заранее подготовленные пакеты (собранные онлайн)
#    Папка offline-packages должна находиться в корне репозитория
COPY ["offline-packages/", "/src/offline-packages/"]

# 3) Полностью офлайн restore (берём пакеты только из /src/offline-packages)
RUN dotnet restore "new_assistant.csproj" --ignore-failed-sources

# 4) Копируем весь исходный код
COPY . .
# Копируем SSL сертификаты в build stage (если папка существует)
COPY ssl/ /src/ssl/

# 5) Сборка и публикация (без повторного restore)
RUN dotnet build "new_assistant.csproj" -c Release -o /app/build --no-restore

# Публикуем приложение
RUN dotnet publish "new_assistant.csproj" -c Release -o /app/publish /p:UseAppHost=false --no-restore

# Используем официальный образ .NET 9.0 runtime для запуска
FROM nexus.ahml.ru/docker-hosted-auth/dom_assistant_new/dotnet-aspnet:9.0 AS final
WORKDIR /app

# Создаем пользователя для безопасности
RUN adduser --disabled-password --gecos '' appuser && \
    mkdir -p /app/data

# Копируем опубликованное приложение
COPY --from=build /app/publish .

# Копируем SSL сертификаты из build stage
COPY --from=build /src/ssl ./ssl

# Устанавливаем права на директорию данных и ssl
RUN mkdir -p /app/ssl && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 9443
ENTRYPOINT ["dotnet", "new_assistant.dll"]
