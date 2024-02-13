import { getUser } from "@/code/auth";
import { getPrisma } from "./withPrisma";

export function withStudentStatus(allowedStatuses = [], handler) {
    const prisma = getPrisma();

    return async (req, res) => {

        const user = await getUser(req, res);
        if(!user) {
            console.log("Access denied due to missing user.");
            return res.status(403).json({ message: "Access denied." });
        }
        const { evaluationId } = req.query; // or get these from the session/user context

        const userOnEvaluation = await prisma.userOnEvaluation.findUnique({
            where: { userEmail_evaluationId: { 
                userEmail: user.email, 
                evaluationId 
            }},
        });

        if (!userOnEvaluation || !allowedStatuses.includes(userOnEvaluation.status)) {
            console.log("Access denied due to student status.", userOnEvaluation, allowedStatuses);
            return res.status(403).json({ message: "Access denied." });
        }

        // Continue with the original handler
        await handler(req, res, prisma);
    };
}

export function withEvaluationPhase(allowedPhases = [], handler) {
    const prisma = getPrisma();

    return async (req, res) => {
        const { evaluationId } = req.query;

        const evaluation = await prisma.evaluation.findUnique({
            where: { id: evaluationId },
        });

        if (!evaluation || !allowedPhases.includes(evaluation.phase)) {
            console.log("Access denied due to evaluation phase.");
            return res.status(403).json({ message: "Access denied due to evaluation phase." });
        }

        // Continue with the original handler if the phase is allowed
        await handler(req, res, prisma);
    };
}
