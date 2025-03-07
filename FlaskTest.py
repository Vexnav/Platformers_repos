from flask import Flask, render_template
app = Flask(__name__)


@app.route('/')
def hello_name():
    return render_template('ViewFlaskTest.html')


if __name__ == '__main__':
    app.run()
