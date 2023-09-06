import { QuestionType, StudentPermission } from '@prisma/client'

export const IncludeStrategy = {
  ALL: 'all',
  USER_SPECIFIC: 'user_specific',
}

const defaultQuestionIncludeClause = {
  includeTypeSpecific: true,
  includeOfficialAnswers: false,
  includeUserAnswers: undefined, // { strategy: IncludeStrategy.USER_SPECIFIC, userEmail: <email> } or { strategy: IncludeStrategy.ALL }
  includeGradings: false,
  includeTags: true,
}

export const questionIncludeClause = (questionIncludeOptions) => {
  // include question related entities based on the specified context

  const options = { ...defaultQuestionIncludeClause, ...questionIncludeOptions }

  const {
    includeTypeSpecific,
    includeOfficialAnswers,
    includeUserAnswers,
    includeGradings,
    includeTags,
  } = options

  const typeSpecific = includeTypeSpecific
    ? {
        code: {
          select: {
            ...(includeOfficialAnswers
              ? {
                  solutionFiles: {
                    include: {
                      file: true,
                    },
                    orderBy: [
                      {
                        file: { createdAt: 'asc' },
                      },
                      {
                        file: { questionId: 'asc' },
                      },
                    ],
                  },
                }
              : {}),
            templateFiles: {
              ...(!includeOfficialAnswers
                ? {
                    where: {
                      studentPermission: {
                        not: StudentPermission.HIDDEN,
                      },
                    },
                  }
                : {}),
              include: {
                file: true,
              },
              orderBy: [
                {
                  file: { createdAt: 'asc' },
                },
                {
                  file: { questionId: 'asc' },
                },
              ],
            },
            language: true,
            sandbox: true,
            testCases: true,
          },
        },
        multipleChoice: {
          select: {
            options: {
              select: {
                id: true,
                text: true,
                ...(includeOfficialAnswers ? { isCorrect: true } : {}),
              },
            },
          },
        },
        trueFalse: {
          select: {
            questionId: true,
            ...(includeOfficialAnswers ? { isTrue: true } : {}),
          },
        },
        essay: true,
        web: true,
        database: {
            select: {
                image: true,
                solutionQueries: {
                    select: {
                        query: {
                            select: {
                                id: true,
                                order: true,
                                title: true,
                                description: true,
                                content: true,
                                template: true,
                                lintRules: true,
                                studentPermission: true,
                                testQuery: true,
                                queryOutputTests: {
                                    select: {
                                        test: true,
                                    }
                                }
                            }
                        },
                        output: true,
                    }

                }
            }
        },
      }
    : {}

  let include = typeSpecific

  if (includeTags) {
    include.questionToTag = {
      include: {
        tag: true,
      },
    }
  }

  if (includeUserAnswers) {
    // no "where" for IncludeStrategy.ALL
    let saWhere =
      includeUserAnswers.strategy === IncludeStrategy.USER_SPECIFIC
        ? {
            userEmail: includeUserAnswers.userEmail,
          }
        : undefined

    include.studentAnswer = {
      where: saWhere,
      select: {
        status: true,
        code: {
          select: {
            files: {
              include: {
                file: true,
              },
              orderBy: [
                {
                  file: { createdAt: 'asc' },
                },
                {
                  file: { questionId: 'asc' },
                },
              ],
            },
            testCaseResults: true,
            allTestCasesPassed: true,
          },
        },
        multipleChoice: {
          select: { options: { select: { id: true, text: true } } },
        },
        essay: { select: { content: true } },
        trueFalse: true,
        web: true,
        user: true,
      },
    }

    // include gradings
    if (includeGradings) {
      include.studentAnswer.select.studentGrading = {
        include: {
          signedBy: true,
        },
      }
    }
  }

  return include
}

/*
    question is the question object from the request body
    question can be null if we are creating a new question
    using this function we can extract the type specific data (and only that) from the question object
    also used to avoid injections
 */
export const questionTypeSpecific = (
  questionType,
  question,
  mode = 'update'
) => {
  switch (questionType) {
    case QuestionType.trueFalse:
      return {
        isTrue: question?.trueFalse.isTrue ?? true,
      }
    case QuestionType.web:
      return {
        html: question?.web.html ?? '',
        css: question?.web.css ?? '',
        js: question?.web.js ?? '',
      }
    case QuestionType.multipleChoice:
      return !question
        ? {
            // default options when creating a new question
            options: {
              create: [
                { text: 'Option 1', isCorrect: false },
                { text: 'Option 2', isCorrect: true },
              ],
            },
          }
        : {
            options:
              mode === 'update'
                ? // multi choice options are no longer managed on the question level, they are managed by individual endpoints : api/questions/:id/multiple-choice/options
                  {}
                : // the only use case for mode === "create" is when we are copying questions for a jam session, see api/jam-sessions [POST]
                  {
                    create: question.multipleChoice.options.map((o) => ({
                      text: o.text,
                      isCorrect: o.isCorrect,
                    })),
                  },
          }
    default:
      return {}
  }
}
