FROM python:3.11-slim

WORKDIR /home/app

# Local-only runtime account and test flag.  The app is a member of `flag` so
# an intended in-app command/file-read test can retrieve the local test flag.
RUN groupadd --system flag \
    && useradd --system --user-group --create-home --home-dir /home/app --groups flag app \
    && printf '%s\n' 'flag{test}' > /flag \
    && chown root:flag /flag \
    && chmod 440 /flag

RUN python3 -m pip install --no-cache-dir flask requests rss-parser

COPY --chown=app:app src/server.py /home/app/server.py
COPY --chown=app:app src/templates /home/app/templates
COPY --chown=app:app src/static /home/app/static

USER app
EXPOSE 31337
ENTRYPOINT ["python3", "-m", "flask", "--app", "/home/app/server.py", "run", "--host", "0.0.0.0", "--port", "31337"]
