# Contributions
## Introduction

It is assumed that you know a little about Node.js and Git. If not, [here's some help to get started with Git](https://help.github.com/en/github/using-git) and [here’s some help to get started with Node.js.](https://nodejs.org/en/docs/guides/getting-started-guide/)

* Install [Node.js](https://nodejs.org/)
* Install [Git](https://git-scm.com/)
* [Fork](https://help.github.com/en/github/getting-started-with-github/fork-a-repo) id-verifier
* Open your OS’s terminal
* Change into the directory you’d like
* Clone your forked repo

      git clone https://github.com/[yourgithubname]/id-verifier.git

* Go into the id-verifier directory.

      cd ./id-verifier

* Install the dependencies

      npm install

## Next Steps

As per the npm standard, ‘start’ is the place to begin the package.

    npm start

This script will start a local server similar to [the demo website](https://universal-verify.github.io/id-verifier/), but instead will be hosted on your local machine. Browse to http://localhost:8000/ to check it out

To verify that you are using a consistent coding style with the rest of the project, run:

      npm run lint

To run a test of the project to prevent regressions, run:

      npm test

If you’d like to make a build of the source files (`build/id-verifier.js` and `build/id-verifier.min.js`) run:

    npm run build

## Making changes

When you’ve decided to make changes, start with the following:

* Update your local repo

      git pull https://github.com/universal-verify/id-verifier.git
      git push

* Make a new branch from the dev branch

      git checkout dev
      git branch [mychangesbranch]
      git checkout [mychangesbranch]

* Add your changes to your commit.
* Push the changes to your forked repo.
* Open a Pull Request (PR)

## Important notes:

* Don't include any build files in your commit
* Pull requests should be with respect to some GitHub issue. Please mention it with a hash (e.g. #2774), If there are no issues for your pull request, please create one first and verify it with the repo owner
* Pull requests should be made to the dev branch unless otherwise decided upon
* If you modify existing code or add new code, please modify or add tests when relevant
