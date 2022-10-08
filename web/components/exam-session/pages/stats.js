import {QuestionType, StudentAnswerStatus, StudentQuestionGradingStatus} from "@prisma/client";

export const getSignedSuccessRate = (questions) => {
    // total signed points
    let totalSignedPoints = questions.reduce((acc, question) => {
        let signedGradings = question.studentAnswer.filter((sa) => sa.studentGrading.signedBy).length;
        return acc + signedGradings * question.points;
    }, 0);
    // total signed obtained points
    let totalSignedObtainedPoints = questions.reduce((acc, question) => acc + question.studentAnswer.filter((sa) => sa.studentGrading.signedBy).reduce((acc, sa) => acc + sa.studentGrading.pointsObtained, 0), 0);
    return totalSignedPoints > 0 ? Math.round(totalSignedObtainedPoints / totalSignedPoints * 100) : 0;
}

export const getObtainedPoints = (questions, participant) => questions.reduce((acc, question) => {
    let studentGrading = question.studentAnswer.find((sa) => sa.user.id === participant.id).studentGrading;
    return acc + (studentGrading ? studentGrading.pointsObtained : 0);
    }, 0);

export const getGradingStats = (questions) => {
    let totalGradings = questions.reduce((acc, question) => acc + question.studentAnswer.length, 0);
    let totalSigned = questions.reduce((acc, question) => acc + question.studentAnswer.filter((sa) => sa.studentGrading.signedBy).length, 0);
    let totalAutogradedUnsigned = questions.reduce((acc, question) => acc + question.studentAnswer.filter((sa) => sa.studentGrading.status === StudentQuestionGradingStatus.AUTOGRADED && !sa.studentGrading.signedBy).length, 0);

    return {
        totalGradings,
        totalSigned,
        totalAutogradedUnsigned
    }
}

export const getQuestionSuccessRate = (question) => {
    let totalPoints = question.points * question.studentAnswer.length;
    let totalObtainedPoints = question.studentAnswer.reduce((acc, sa) => acc + sa.studentGrading.pointsObtained, 0);
    return totalPoints > 0 ? Math.round(totalObtainedPoints / totalPoints * 100) : 0;
}

export const typeSpecificStats = (question) => {
    switch(question.type) {
        case QuestionType.multipleChoice:
            return question[question.type].options.map((option, index) => {
                // number of times this option was selected in student answers
                let chosen = question.studentAnswer.reduce((acc, sa) => {
                    if(sa.status === StudentAnswerStatus.SUBMITTED) {
                        let isChosen = sa[question.type].options.some((o) => o.id === option.id);
                        if(isChosen) {
                            return acc + 1;
                        }
                    }
                    return acc;
                }, 0);
                return {
                    label: `O${index + 1}`,
                    chosen
                }
            });
        case QuestionType.trueFalse:
            let trueChosen = question.studentAnswer.reduce((acc, sa) => {
                if(sa.status === StudentAnswerStatus.SUBMITTED && sa[question.type].isTrue) {
                    return acc + 1;
                }
                return acc;
            }, 0);
            let falseChosen = question.studentAnswer.reduce((acc, sa) => {
                if(sa.status === StudentAnswerStatus.SUBMITTED && !sa[question.type].isTrue) {
                    return acc + 1;
                }
                return acc;

            }, 0);
            return {
                true: {
                    chosen: trueChosen
                },
                false: {
                    chosen: falseChosen
                }
            }
        case QuestionType.code:
            let success  = question.studentAnswer.reduce((acc, sa) => {
                if(sa.status === StudentAnswerStatus.SUBMITTED && sa[question.type].success) {
                    return acc + 1;
                }
                return acc;
            }, 0);
            let failure = question.studentAnswer.reduce((acc, sa) => {
                if(sa.status === StudentAnswerStatus.SUBMITTED && !sa[question.type].success) {
                    return acc + 1;
                }
                return acc;
            }, 0);
            return {
                success: {
                    accomplished: success
                },
                failure: {
                    accomplished: failure
                }
            }
        default:
            return null
    }
}