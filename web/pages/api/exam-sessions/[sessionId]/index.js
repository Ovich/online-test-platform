import { PrismaClient, Role, ExamSessionPhase } from '@prisma/client';

import { hasRole } from '../../../../utils/auth';

if (!global.prisma) {
    global.prisma = new PrismaClient()
}

const prisma = global.prisma

const handler = async (req, res) => {
    const isProf = await hasRole(req, Role.PROFESSOR);
    if(!isProf){
        res.status(401).json({ message: 'Unauthorized' });
        return;
    }
    
    switch(req.method) {
        case 'GET':
            await get(req, res);
            break;
        case 'PATCH':
            await patch(req, res);
            break;
        case 'DELETE':
            await del(req, res);
            break;
        default:
    }
}

const get = async (req, res) => {
    
    
    const { sessionId } = req.query;
    const exam = await prisma.examSession.findUnique({
        where: {
            id: sessionId
        },
        include: {
            students: {
                select: {
                    user: true
                }   
            }
        }
    });
    res.status(200).json(exam);
}

const patch = async (req, res) => {
   
    const { sessionId } = req.query

    const currentExamSession = await prisma.examSession.findUnique({
        where: {
            id: sessionId
        },
        select: {
            phase: true,
            startAt: true,
            durationHours: true,
            durationMins: true
        }
    });    
    
    if(!currentExamSession) {
        res.status(404).json({ message: 'Exam session not found' });
        return;
    }

    const { phase:nextPhase, label, conditions, duration, endAt, status } = req.body;
    
    let data = {};

    if(nextPhase){
        data.phase = nextPhase;
        if(nextPhase === ExamSessionPhase.IN_PROGRESS){
            // handle start and end time
            let durationHours = currentExamSession.durationHours;
            let durationMins = currentExamSession.durationMins;
            if(durationHours > 0 || durationMins > 0){
                data.startAt = new Date();
                data.endAt = new Date(Date.now() + (durationHours * 3600000) + (durationMins * 60000));
            }else{
                data.startAt = null;
                data.endAt = null;
            }
        }
    }

    if(label){
        data.label = label;
    }

    if(conditions){
        data.conditions = conditions;
    }

    if(status){
        data.status = status;
    }

    if(duration){
        data.durationHours = duration.hours;
        data.durationMins = duration.minutes;
    }

    if(endAt){
        let startAt = new Date(currentExamSession.startAt);
        let newEndAt = new Date(endAt);
        if(newEndAt < startAt){
            res.status(400).json({ message: 'End time must be after start time' });
            return;
        }
        data.endAt = endAt;
    }

    try {
        const examSessionAfterUpdate = await prisma.examSession.update({
            where: {
                id: sessionId
            },
            data: data
        });           
        res.status(200).json(examSessionAfterUpdate);
    } catch (e) {
        switch(e.code){
            case 'P2002':
                res.status(409).json({ message: 'Exam session label already exists' });
                break;
            default:
                res.status(500).json({ message: 'Error while updating exam session' });
                break;
        }
    }    
}

const del = async (req, res) => {
    const isProf = await hasRole(req, Role.PROFESSOR);
    if(!isProf){
        res.status(401).json({ message: 'Unauthorized' });
        return;
    }
    const { sessionId } = req.query
    const examSession = await prisma.examSession.delete({
        where: {
            id: sessionId
        }
    });
    res.status(200).json(examSession);
}

export default handler;