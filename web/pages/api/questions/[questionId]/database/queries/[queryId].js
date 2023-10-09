import {DatabaseQueryOutputTest, PrismaClient, Role, JsonNull} from '@prisma/client'

import { hasRole } from '../../../../../../code/auth'

if (!global.prisma) {
  global.prisma = new PrismaClient()
}

const prisma = global.prisma

// hanlder for POST, GET

const handler = async (req, res) => {
  if (!(await hasRole(req, Role.PROFESSOR))) {
    res.status(401).json({ message: 'Unauthorized' })
    return
  }
  switch (req.method) {
    case 'GET':
        await get(req, res)
        break
    case 'PUT':
        await put(req, res)
        break
    case 'DELETE':
        await del(req, res)
        break
    default:
        res.status(405).json({ message: 'Method not allowed' })
    }
}

const put = async (req, res) => {
  // update a query for a database question

  const { questionId, queryId } = req.query
    const {
        title,
        description,
        content,
        template,
        lintActive,
        lintRules,
        studentPermission,
        queryOutputTests,
        testQuery
  } = req.body

    // check if the query belongs to the question
    const checkQuery = await prisma.databaseQuery.findUnique({
        where: {
            id: queryId
        }
    });

    if (!checkQuery) {
        res.status(404).json({ message: 'Not found' })
        return
    }

    if (checkQuery.questionId !== questionId) {
        res.status(404).json({ message: 'Not found' })
        return
    }

    const data = {
        title: title,
        description: description,
        content: content,
        template: template,
        lintActive: lintActive,
        lintRules: lintRules,
        studentPermission: studentPermission,
        testQuery: testQuery,
        queryOutputTests: {
            deleteMany: {},
            create: queryOutputTests.map(queryOutputTest => ({ test: DatabaseQueryOutputTest[queryOutputTest.test] }))
        }
    }
    
    if (!lintActive) {
        data.lintResult = JsonNull
    }

    const query = await prisma.databaseQuery.update({
        where: {
            id: queryId
        },
        data: data
    });

    res.status(200).json(query)
}

const del = async (req, res) => {
  // DELETE a query for a database question

    const { questionId, queryId } = req.query

    // check if the query belongs to the question
    const checkQuery = await prisma.databaseQuery.findUnique({
        where: {
            id: queryId
        }
    });

    if (!checkQuery) {
        res.status(404).json({ message: 'Not found' })
        return
    }

    if (checkQuery.questionId !== questionId) {
        res.status(404).json({ message: 'Not found' })
        return
    }

    let query;

    await prisma.$transaction(async (prisma) => {

        query = await prisma.databaseQuery.delete({
            where: {
                id: queryId
            }
        });

        // decrease the order of the queries that have a greater order than the deleted query
        const solQueries = await prisma.databaseToSolutionQuery.findMany({
            where: {
                questionId: questionId,
            },
            include: {
                query: true,
            },
            orderBy: {
                query: {
                    order: 'asc',
                }
            }
        });
        for (let i = 0; i < solQueries.length; i++) {
            const solQuery = solQueries[i];

            await prisma.databaseQuery.update({
                where: {
                    id: solQuery.query.id,
                },
                data: {
                    order: i + 1,  // Set order to index + 1 to make it 1-indexed
                },
            });
        }

    });

    res.status(200).json(query)
}

export default handler
